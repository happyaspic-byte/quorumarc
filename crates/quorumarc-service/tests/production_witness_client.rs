#![allow(clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use quorumarc_runtime::{VoteReasonCode, WitnessPolicy};
use quorumarc_service::config::ProductionConfig;
use quorumarc_service::protocol::{ProductionRequest, ProductionVotePayload};
use quorumarc_service::signal::ShutdownToken;
use quorumarc_service::tls::{client_mtls_config, server_mtls_config};
use quorumarc_service::witness::{
    CandidateCredential, ProductionWitnessRuntime, ProductionWitnessServer, WitnessMembership,
};
use quorumarc_service::witness_client::{
    ProductionWitnessClient, WitnessClientError, WitnessIdentity, assemble_production_certificate,
};
use quorumarc_store::{StoreIdentity, StoreRole};
use quorumarc_wire::{CanonicalId, VerificationKeyResolver};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConnection, StreamOwned};

struct IssuedIdentity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

struct TwoKeyResolver {
    candidate_id: CanonicalId,
    candidate_key_id: CanonicalId,
    candidate_key: ed25519_dalek::VerifyingKey,
    witness_id: CanonicalId,
    witness_key_id: CanonicalId,
    witness_key: ed25519_dalek::VerifyingKey,
}

impl VerificationKeyResolver for TwoKeyResolver {
    fn resolve(
        &self,
        principal: &CanonicalId,
        key_id: &CanonicalId,
    ) -> Option<ed25519_dalek::VerifyingKey> {
        if principal == &self.candidate_id && key_id == &self.candidate_key_id {
            Some(self.candidate_key)
        } else if principal == &self.witness_id && key_id == &self.witness_key_id {
            Some(self.witness_key)
        } else {
            None
        }
    }
}

#[test]
fn production_witness_client_builds_from_data_node_config_and_declared_witness_identity() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-witness-client-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let store = directory.join("store");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");
    let candidate = SigningKey::from_bytes(&[7; 32]);
    let other_candidate = SigningKey::from_bytes(&[9; 32]);
    let witness = SigningKey::from_bytes(&[29; 32]);
    let candidate_seed = directory.join("node-a.seed");
    let candidate_public = directory.join("node-a.pub");
    let other_public = directory.join("node-b.pub");
    let witness_public = directory.join("witness.pub");
    write_private(&candidate_seed, &candidate.to_bytes());
    fs::write(&candidate_public, candidate.verifying_key().to_bytes()).expect("candidate public");
    fs::write(&other_public, other_candidate.verifying_key().to_bytes()).expect("other public");
    fs::write(&witness_public, witness.verifying_key().to_bytes()).expect("witness public");
    let (ca, server_identity, client_identity) = issue_identities();
    let client_certificate = directory.join("node-a.crt");
    let client_private_key = directory.join("node-a.key");
    let trusted_roots = directory.join("ca.crt");
    fs::write(
        &client_certificate,
        pem("CERTIFICATE", client_identity.certificate.as_ref()),
    )
    .expect("client cert");
    let client_key_der = client_identity.key.secret_der();
    write_private(
        &client_private_key,
        pem("PRIVATE KEY", client_key_der).as_bytes(),
    );
    fs::write(&trusted_roots, pem("CERTIFICATE", ca.as_ref())).expect("ca");
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let witness_address = listener.local_addr().expect("address");
    drop(listener);
    let config_text = data_node_config(
        &directory,
        witness_address,
        &candidate_seed,
        &candidate_public,
        &other_public,
        &witness_public,
        &client_certificate,
        &client_private_key,
        &trusted_roots,
    );
    let config = ProductionConfig::parse(&config_text).expect("config");

    let (_client, identity) =
        ProductionWitnessClient::from_config(&config).expect("client from config");
    assert_eq!(identity.witness_id().as_str(), "witness-a");
    assert_eq!(identity.key_id().as_str(), "witness-2026-01");
    assert_eq!(identity.verifying_key(), &witness.verifying_key());
    drop(server_identity);
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn production_witness_client_returns_verified_cluster_bound_certificate() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-witness-client-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let candidate = SigningKey::from_bytes(&[7; 32]);
    let other_candidate = SigningKey::from_bytes(&[9; 32]);
    let witness = SigningKey::from_bytes(&[29; 32]);
    let runtime = vote_runtime(&directory, &candidate, &other_candidate, witness.clone());
    let (ca, server_identity, client_identity) = issue_identities();
    let server_tls = server_mtls_config(
        vec![server_identity.certificate],
        server_identity.key,
        vec![ca.clone()],
    )
    .expect("server TLS");
    let client_tls = client_mtls_config(
        vec![client_identity.certificate],
        client_identity.key,
        vec![ca],
    )
    .expect("client TLS");
    let server =
        ProductionWitnessServer::bind(membership(), server_tls, runtime, Duration::from_secs(1))
            .expect("bind");
    let address = server.local_addr().expect("address");
    let shutdown = ShutdownToken::new();
    let server_shutdown = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&server_shutdown));

    let witness_identity =
        WitnessIdentity::new("witness-a", "witness-2026-01", witness.verifying_key())
            .expect("witness identity");
    let client = ProductionWitnessClient::new(
        address,
        "witness.test",
        Arc::new(client_tls),
        Duration::from_secs(1),
    )
    .expect("client");
    let request = ProductionRequest {
        cluster_id: "prod-cluster".to_owned(),
        workload_id: "orders-api".to_owned(),
        node_id: "node-a".to_owned(),
        key_id: "node-a-2026-01".to_owned(),
        request_id: [61; 16],
        sequence: 1,
        incarnation: 1,
        epoch: 1,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
            .expect("payload")
            .encode(),
    };

    let reply = client
        .request_vote(request.clone(), &candidate, &witness_identity)
        .expect("verified Witness vote");
    assert_eq!(reply.code(), VoteReasonCode::GrantedDurablyRecorded);
    let certificate =
        assemble_production_certificate(&request, &candidate, &witness_identity, reply)
            .expect("certificate");
    assert_eq!(certificate.cluster_id().as_str(), "prod-cluster");
    assert_eq!(certificate.threshold(), 2);
    assert_eq!(certificate.votes().len(), 2);
    let resolver = TwoKeyResolver {
        candidate_id: canonical_id("node-a"),
        candidate_key_id: canonical_id("node-a-2026-01"),
        candidate_key: candidate.verifying_key(),
        witness_id: canonical_id("witness-a"),
        witness_key_id: canonical_id("witness-2026-01"),
        witness_key: witness.verifying_key(),
    };
    certificate.verify(&resolver).expect("verified certificate");

    shutdown.request();
    server_thread.join().expect("server thread").expect("serve");
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn production_witness_client_exact_retry_returns_same_durable_vote() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-witness-client-retry-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let candidate = SigningKey::from_bytes(&[7; 32]);
    let other_candidate = SigningKey::from_bytes(&[9; 32]);
    let witness = SigningKey::from_bytes(&[29; 32]);
    let runtime = vote_runtime(&directory, &candidate, &other_candidate, witness.clone());
    let (ca, server_identity, client_identity) = issue_identities();
    let server_tls = server_mtls_config(
        vec![server_identity.certificate],
        server_identity.key,
        vec![ca.clone()],
    )
    .expect("server TLS");
    let client_tls = client_mtls_config(
        vec![client_identity.certificate],
        client_identity.key,
        vec![ca],
    )
    .expect("client TLS");
    let server =
        ProductionWitnessServer::bind(membership(), server_tls, runtime, Duration::from_secs(1))
            .expect("bind");
    let address = server.local_addr().expect("address");
    let shutdown = ShutdownToken::new();
    let server_shutdown = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&server_shutdown));
    let identity = WitnessIdentity::new("witness-a", "witness-2026-01", witness.verifying_key())
        .expect("identity");
    let client = ProductionWitnessClient::new(
        address,
        "witness.test",
        Arc::new(client_tls),
        Duration::from_secs(1),
    )
    .expect("client");
    let request = ProductionRequest {
        cluster_id: "prod-cluster".to_owned(),
        workload_id: "orders-api".to_owned(),
        node_id: "node-a".to_owned(),
        key_id: "node-a-2026-01".to_owned(),
        request_id: [61; 16],
        sequence: 1,
        incarnation: 1,
        epoch: 1,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
            .expect("payload")
            .encode(),
    };

    let committed = client
        .request_vote(request.clone(), &candidate, &identity)
        .expect("committed");
    let retried = client
        .request_vote(request, &candidate, &identity)
        .expect("retried");
    assert_eq!(committed.code(), VoteReasonCode::GrantedDurablyRecorded);
    assert_eq!(retried.code(), VoteReasonCode::GrantedAlreadyDurable);
    assert_eq!(retried.signed_vote(), committed.signed_vote());
    assert_eq!(retried.durable_generation(), committed.durable_generation());

    shutdown.request();
    server_thread.join().expect("server thread").expect("serve");
    fs::remove_dir_all(directory).expect("cleanup");
}

#[test]
fn production_witness_client_refuses_cross_cluster_vote_reply_replay() {
    let candidate = SigningKey::from_bytes(&[7; 32]);
    let witness = SigningKey::from_bytes(&[29; 32]);
    let (ca, server_identity, client_identity) = issue_identities();
    let server_tls = server_mtls_config(
        vec![server_identity.certificate],
        server_identity.key,
        vec![ca.clone()],
    )
    .expect("server TLS");
    let client_tls = client_mtls_config(
        vec![client_identity.certificate],
        client_identity.key,
        vec![ca],
    )
    .expect("client TLS");

    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("address");
    let candidate_for_server = candidate.clone();
    let witness_clone = witness.clone();
    let server_handle = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let connection = ServerConnection::new(server_tls.into_arc()).expect("server connection");
        let mut tls = StreamOwned::new(connection, stream);
        let mut len_bytes = [0_u8; 4];
        tls.read_exact(&mut len_bytes).expect("read len");
        let len = u32::from_be_bytes(len_bytes) as usize;
        let mut frame = vec![0_u8; len];
        tls.read_exact(&mut frame).expect("read frame");

        let reply_directory = std::env::temp_dir().join(format!(
            "quorumarc-production-cross-cluster-{}",
            std::process::id()
        ));
        fs::create_dir_all(&reply_directory).expect("dir");
        let other_runtime = ProductionWitnessRuntime::open_vote_actor(
            &reply_directory,
            StoreIdentity::new(
                "other-cluster",
                "orders-api",
                "witness-a",
                StoreRole::Witness,
                [52; 16],
            )
            .expect("identity"),
            WitnessPolicy::new(
                canonical_id("witness-a"),
                canonical_id("witness-2026-01"),
                canonical_id("orders-api"),
                [23; 32],
                [canonical_id("node-a"), canonical_id("node-b")],
                5_000,
            )
            .expect("policy"),
            witness_clone,
            [
                CandidateCredential::new(
                    "node-a",
                    "node-a-2026-01",
                    candidate_for_server.verifying_key(),
                )
                .expect("node a"),
                CandidateCredential::new(
                    "node-b",
                    "node-b-2026-01",
                    SigningKey::from_bytes(&[9; 32]).verifying_key(),
                )
                .expect("node b"),
            ],
        )
        .expect("runtime");
        drop(other_runtime);
        let mut other_runtime = ProductionWitnessRuntime::open_vote_actor(
            &reply_directory,
            StoreIdentity::new(
                "other-cluster",
                "orders-api",
                "witness-a",
                StoreRole::Witness,
                [52; 16],
            )
            .expect("identity"),
            WitnessPolicy::new(
                canonical_id("witness-a"),
                canonical_id("witness-2026-01"),
                canonical_id("orders-api"),
                [23; 32],
                [canonical_id("node-a"), canonical_id("node-b")],
                5_000,
            )
            .expect("policy"),
            SigningKey::from_bytes(&[29; 32]),
            [
                CandidateCredential::new(
                    "node-a",
                    "node-a-2026-01",
                    candidate_for_server.verifying_key(),
                )
                .expect("node a"),
                CandidateCredential::new(
                    "node-b",
                    "node-b-2026-01",
                    SigningKey::from_bytes(&[9; 32]).verifying_key(),
                )
                .expect("node b"),
            ],
        )
        .expect("runtime");
        let other_request = quorumarc_service::protocol::ProductionFrame::sign(
            quorumarc_service::protocol::ProductionFrameKind::Request,
            ProductionRequest {
                cluster_id: "other-cluster".to_owned(),
                workload_id: "orders-api".to_owned(),
                node_id: "node-a".to_owned(),
                key_id: "node-a-2026-01".to_owned(),
                request_id: [61; 16],
                sequence: 1,
                incarnation: 1,
                epoch: 1,
                progress_commit: 12,
                policy_hash: [23; 32],
                payload: ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
                    .expect("payload")
                    .encode(),
            },
            &candidate_for_server,
        )
        .expect("sign")
        .encode()
        .expect("encode");
        let foreign_reply = other_runtime.handle_vote(&other_request).expect("vote");
        let encoded = foreign_reply.encode().expect("encode");
        let len = u32::try_from(encoded.len()).expect("len");
        tls.write_all(&len.to_be_bytes()).expect("write");
        tls.write_all(&encoded).expect("write body");
        tls.flush().expect("flush");
        let _ = fs::remove_dir_all(reply_directory);
    });

    let witness_identity =
        WitnessIdentity::new("witness-a", "witness-2026-01", witness.verifying_key())
            .expect("witness identity");
    let client = ProductionWitnessClient::new(
        address,
        "witness.test",
        Arc::new(client_tls),
        Duration::from_secs(1),
    )
    .expect("client");
    let request = ProductionRequest {
        cluster_id: "prod-cluster".to_owned(),
        workload_id: "orders-api".to_owned(),
        node_id: "node-a".to_owned(),
        key_id: "node-a-2026-01".to_owned(),
        request_id: [61; 16],
        sequence: 1,
        incarnation: 1,
        epoch: 1,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
            .expect("payload")
            .encode(),
    };

    let result = client.request_vote(request, &candidate, &witness_identity);
    assert_eq!(result, Err(WitnessClientError::AuthenticationFailed));
    assert!(!WitnessClientError::AuthenticationFailed.is_node_failure_suspicion());
    server_handle.join().expect("server handle");
}

fn vote_runtime(
    directory: &std::path::Path,
    candidate: &SigningKey,
    other_candidate: &SigningKey,
    witness: SigningKey,
) -> ProductionWitnessRuntime {
    let policy = WitnessPolicy::new(
        canonical_id("witness-a"),
        canonical_id("witness-2026-01"),
        canonical_id("orders-api"),
        [23; 32],
        [canonical_id("node-a"), canonical_id("node-b")],
        5_000,
    )
    .expect("policy");
    let identity = StoreIdentity::new(
        "prod-cluster",
        "orders-api",
        "witness-a",
        StoreRole::Witness,
        [51; 16],
    )
    .expect("identity");
    ProductionWitnessRuntime::open_vote_actor(
        directory,
        identity,
        policy,
        witness,
        [
            CandidateCredential::new("node-a", "node-a-2026-01", candidate.verifying_key())
                .expect("node a"),
            CandidateCredential::new("node-b", "node-b-2026-01", other_candidate.verifying_key())
                .expect("node b"),
        ],
    )
    .expect("runtime")
}

fn membership() -> WitnessMembership {
    WitnessMembership::new(
        "node-a",
        "127.0.0.2:7601".parse().expect("node a"),
        "power-a",
        "node-b",
        "127.0.0.3:7601".parse().expect("node b"),
        "power-b",
        "witness-a",
        "127.0.0.1:0".parse().expect("witness"),
        "power-w",
    )
    .expect("membership")
}

fn canonical_id(value: &str) -> CanonicalId {
    CanonicalId::new(value).expect("canonical id")
}

fn issue_identities() -> (CertificateDer<'static>, IssuedIdentity, IssuedIdentity) {
    let mut ca_params = CertificateParams::new(vec!["quorumarc-ca".to_owned()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let server = issue_identity(
        "witness.test",
        ExtendedKeyUsagePurpose::ServerAuth,
        &ca,
        &ca_key,
    );
    let client = issue_identity(
        "node-a.test",
        ExtendedKeyUsagePurpose::ClientAuth,
        &ca,
        &ca_key,
    );
    (CertificateDer::from(ca.der().to_vec()), server, client)
}

fn issue_identity(
    name: &str,
    usage: ExtendedKeyUsagePurpose,
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
) -> IssuedIdentity {
    let mut params = CertificateParams::new(vec![name.to_owned()]).expect("params");
    params.extended_key_usages = vec![usage];
    let key = KeyPair::generate().expect("key");
    let certificate = params.signed_by(&key, ca, ca_key).expect("signed");
    IssuedIdentity {
        certificate: CertificateDer::from(certificate.der().to_vec()),
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write private");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("mode");
}

fn pem(tag: &str, der: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = format!("-----BEGIN {tag}-----\n");
    let encoded = base64_encode(der);
    for chunk in encoded.as_bytes().chunks(64) {
        let line = std::str::from_utf8(chunk).expect("utf8");
        let _ = writeln!(text, "{line}");
    }
    let _ = writeln!(text, "-----END {tag}-----");
    text
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TABLE[((triple >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn data_node_config(
    directory: &std::path::Path,
    witness_address: std::net::SocketAddr,
    signing_key: &std::path::Path,
    candidate_public: &std::path::Path,
    other_public: &std::path::Path,
    witness_public: &std::path::Path,
    certificate_chain: &std::path::Path,
    private_key: &std::path::Path,
    trusted_roots: &std::path::Path,
) -> String {
    let store_dir = directory.join("store");
    format!(
        r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "127.0.0.2:7601"
witness = "{witness_address}"
store_dir = "{}"
store_id = "07070707070707070707070707070707"
signing_key = "{}"
key_id = "node-a-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = false
[tls]
certificate_chain = "{}"
private_key = "{}"
trusted_roots = "{}"
server_name = "witness.test"
io_timeout_ms = 1000
[fence]
mechanism = "hardware-power"
profile = "pdu-a"
read_back = true
[workload]
unit = "orders-api.service"
[effect]
vip = "127.0.0.100/24"
interface = "lo"
[[members]]
id = "node-a"
role = "data"
address = "127.0.0.2:7601"
failure_domain = "power-a"
key_id = "node-a-2026-01"
public_key = "{}"
[[members]]
id = "node-b"
role = "data"
address = "127.0.0.3:7601"
failure_domain = "power-b"
key_id = "node-b-2026-01"
public_key = "{}"
[[members]]
id = "witness-a"
role = "witness"
address = "{witness_address}"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "{}"
"#,
        store_dir.display(),
        signing_key.display(),
        certificate_chain.display(),
        private_key.display(),
        trusted_roots.display(),
        candidate_public.display(),
        other_public.display(),
        witness_public.display(),
    )
}
