#![allow(clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, StreamOwned};

use quorumarc_runtime::{VoteReasonCode, WitnessPolicy};
use quorumarc_service::protocol::{
    ProductionFrame, ProductionFrameKind, ProductionRequest, ProductionVotePayload,
};
use quorumarc_service::signal::ShutdownToken;
use quorumarc_service::tls::{client_mtls_config, server_mtls_config};
use quorumarc_service::witness::{
    CandidateCredential, ProductionVoteReply, ProductionWitnessRuntime, ProductionWitnessServer,
    WitnessMembership,
};
use quorumarc_store::{StoreIdentity, StoreRole};
use quorumarc_wire::CanonicalId;

struct IssuedIdentity {
    certificate: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
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

fn signed_request(
    sequence: u64,
    request_id: [u8; 16],
    payload: &[u8],
    key: &SigningKey,
) -> Vec<u8> {
    ProductionFrame::sign(
        ProductionFrameKind::Request,
        ProductionRequest {
            cluster_id: "prod-cluster".to_owned(),
            workload_id: "orders-api".to_owned(),
            node_id: "node-a".to_owned(),
            key_id: "node-a-2026-01".to_owned(),
            request_id,
            sequence,
            incarnation: 1,
            epoch: 1,
            progress_commit: 12,
            policy_hash: [23; 32],
            payload: payload.to_vec(),
        },
        key,
    )
    .expect("sign")
    .encode()
    .expect("encode")
}

fn connect_retry(address: SocketAddr) -> std::io::Result<TcpStream> {
    for _ in 0..50 {
        if let Ok(stream) = TcpStream::connect(address) {
            return Ok(stream);
        }
        thread::sleep(Duration::from_millis(10));
    }
    TcpStream::connect(address)
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

fn vote_runtime(
    directory: &std::path::Path,
    node_a: &SigningKey,
    node_b: &SigningKey,
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
        SigningKey::from_bytes(&[29; 32]),
        [
            CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
                .expect("node a"),
            CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
                .expect("node b"),
        ],
    )
    .expect("vote runtime")
}

fn signed_vote_request(key: &SigningKey) -> Vec<u8> {
    let payload = ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
        .expect("payload")
        .encode();
    signed_request(1, [61; 16], &payload, key)
}

fn write_frame(tls: &mut StreamOwned<ClientConnection, TcpStream>, frame: &[u8]) {
    let len = u32::try_from(frame.len()).expect("len");
    tls.write_all(&len.to_be_bytes()).expect("write len");
    tls.write_all(frame).expect("write body");
    tls.flush().expect("flush");
}

fn read_status(tls: &mut StreamOwned<ClientConnection, TcpStream>) -> Vec<u8> {
    let mut len_bytes = [0_u8; 4];
    tls.read_exact(&mut len_bytes).expect("read resp len");
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut body = vec![0_u8; len];
    tls.read_exact(&mut body).expect("read resp body");
    body
}

#[test]
fn production_witness_server_refuses_runtime_identity_mismatch_with_membership() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-identity-mismatch-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_x = SigningKey::from_bytes(&[17; 32]);
    let node_y = SigningKey::from_bytes(&[19; 32]);
    let policy = WitnessPolicy::new(
        canonical_id("witness-x"),
        canonical_id("witness-x-key"),
        canonical_id("orders-api"),
        [23; 32],
        [canonical_id("node-x"), canonical_id("node-y")],
        5_000,
    )
    .expect("policy");
    let identity = StoreIdentity::new(
        "prod-cluster",
        "orders-api",
        "witness-x",
        StoreRole::Witness,
        [71; 16],
    )
    .expect("identity");
    let runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity,
        policy,
        SigningKey::from_bytes(&[29; 32]),
        [
            CandidateCredential::new("node-x", "node-x-key", node_x.verifying_key())
                .expect("node x"),
            CandidateCredential::new("node-y", "node-y-key", node_y.verifying_key())
                .expect("node y"),
        ],
    )
    .expect("runtime");
    let (ca, server_id, _) = issue_identities();
    let tls =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca]).expect("tls");
    assert!(matches!(
        ProductionWitnessServer::bind(membership(), tls, runtime, Duration::from_secs(1)),
        Err(quorumarc_service::witness::WitnessServerError::InvalidRuntime)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_refuses_policy_candidate_mismatch_with_membership() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-policy-membership-mismatch-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let policy = WitnessPolicy::new(
        canonical_id("witness-a"),
        canonical_id("witness-2026-01"),
        canonical_id("orders-api"),
        [23; 32],
        [canonical_id("node-a")],
        5_000,
    )
    .expect("policy");
    let identity = StoreIdentity::new(
        "prod-cluster",
        "orders-api",
        "witness-a",
        StoreRole::Witness,
        [72; 16],
    )
    .expect("identity");
    let runtime = ProductionWitnessRuntime::open_vote_actor(
        &directory,
        identity,
        policy,
        SigningKey::from_bytes(&[29; 32]),
        [
            CandidateCredential::new("node-a", "node-a-2026-01", node_a.verifying_key())
                .expect("node a"),
            CandidateCredential::new("node-b", "node-b-2026-01", node_b.verifying_key())
                .expect("node b"),
        ],
    )
    .expect("runtime");
    let (ca, server_id, _) = issue_identities();
    let tls =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca]).expect("tls");
    assert!(matches!(
        ProductionWitnessServer::bind(membership(), tls, runtime, Duration::from_secs(1)),
        Err(quorumarc_service::witness::WitnessServerError::InvalidRuntime)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_honors_configured_io_timeout() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-configured-timeout-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &node_a, &node_b);
    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");
    let server = ProductionWitnessServer::bind(
        membership(),
        server_config,
        runtime,
        Duration::from_millis(1_000),
    )
    .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&shutdown_clone));

    let stream = connect_retry(listen_addr).expect("connect");
    thread::sleep(Duration::from_millis(700));
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &signed_vote_request(&node_a));
    let reply = ProductionVoteReply::decode(&read_status(&mut tls)).expect("vote reply");
    assert!(reply.is_granted());

    shutdown.request();
    server_thread.join().expect("server thread").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_returns_signed_policy_checked_vote_over_mtls() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-signed-vote-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &node_a, &node_b);
    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");
    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&shutdown_clone));

    let stream = connect_retry(listen_addr).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &signed_vote_request(&node_a));
    let reply = ProductionVoteReply::decode(&read_status(&mut tls)).expect("vote reply");
    assert_eq!(reply.code(), VoteReasonCode::GrantedDurablyRecorded);
    assert!(reply.signed_vote().is_some());
    assert_eq!(reply.binding().candidate_node_id.as_str(), "node-a");

    shutdown.request();
    server_thread.join().expect("server thread").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_exact_vote_retry_returns_same_signed_vote() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-witness-retry-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let node_a = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &node_a, &node_b);
    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");
    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&shutdown_clone));
    let first = signed_vote_request(&node_a);

    let stream = connect_retry(listen_addr).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config.clone()), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &first);
    let committed = ProductionVoteReply::decode(&read_status(&mut tls)).expect("committed");
    assert_eq!(committed.code(), VoteReasonCode::GrantedDurablyRecorded);

    let stream2 = connect_retry(listen_addr).expect("connect 2");
    let server_name2 = ServerName::try_from("witness.test").expect("server name");
    let connection2 =
        ClientConnection::new(Arc::new(client_config), server_name2).expect("client TLS 2");
    let mut tls2 = StreamOwned::new(connection2, stream2);
    write_frame(&mut tls2, &first);
    let retried = ProductionVoteReply::decode(&read_status(&mut tls2)).expect("retry");
    assert_eq!(retried.code(), VoteReasonCode::GrantedAlreadyDurable);
    assert_eq!(retried.signed_vote(), committed.signed_vote());
    assert_eq!(retried.durable_generation(), committed.durable_generation());

    shutdown.request();
    server_thread.join().expect("server thread").expect("serve");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_refuses_untrusted_client_certificate() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-server-untrusted-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &key, &node_b);

    let (trusted_ca, server_id, _) = issue_identities();
    let (_, _, untrusted_client) = issue_identities();
    let server_config = server_mtls_config(
        vec![server_id.certificate],
        server_id.key,
        vec![trusted_ca.clone()],
    )
    .expect("server config");
    let client_config = client_mtls_config(
        vec![untrusted_client.certificate],
        untrusted_client.key,
        vec![trusted_ca],
    )
    .expect("client config");

    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || {
        server.serve_until(&shutdown_clone).expect("serve");
    });

    let first = signed_vote_request(&key);
    let stream = connect_retry(listen_addr).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    let write_result = {
        let len = u32::try_from(first.len()).expect("len");
        tls.write_all(&len.to_be_bytes())
            .and_then(|()| tls.write_all(&first))
            .and_then(|()| tls.flush())
    };
    let mut response = [0_u8; 1];
    assert!(write_result.is_err() || tls.read_exact(&mut response).is_err());

    shutdown.request();
    server_thread.join().expect("server thread");

    let resumed = vote_runtime(&directory, &key, &node_b);
    assert_eq!(resumed.highest_epoch(), 0);
    assert!(!resumed.effects_open());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_rejects_non_vote_max_payload_without_advancing_epoch() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-server-max-payload-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &key, &node_b);

    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");
    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || {
        server.serve_until(&shutdown_clone).expect("serve");
    });

    let payload = vec![0x5a_u8; 65_536];
    let first = signed_request(1, [11; 16], &payload, &key);
    assert!(first.len() > 65_536);
    let stream = connect_retry(listen_addr).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &first);
    assert_eq!(read_status(&mut tls), b"MALFORMED\n");

    shutdown.request();
    server_thread.join().expect("server thread");
    let resumed = vote_runtime(&directory, &key, &node_b);
    assert_eq!(resumed.highest_epoch(), 0);
    assert!(!resumed.effects_open());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_idle_peer_does_not_block_authenticated_vote() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-server-idle-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &key, &node_b);

    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");
    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || {
        server.serve_until(&shutdown_clone).expect("serve");
    });

    let idle = connect_retry(listen_addr).expect("idle connect");
    let started = std::time::Instant::now();
    let first = signed_vote_request(&key);
    let stream = connect_retry(listen_addr).expect("vote connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &first);
    let reply = ProductionVoteReply::decode(&read_status(&mut tls)).expect("vote reply");
    assert_eq!(reply.code(), VoteReasonCode::GrantedDurablyRecorded);
    assert!(started.elapsed() < Duration::from_millis(200));
    drop(idle);

    shutdown.request();
    server_thread.join().expect("server thread");
    let resumed = vote_runtime(&directory, &key, &node_b);
    assert_eq!(resumed.highest_epoch(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_server_shutdown_closes_and_joins_idle_workers() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-server-shutdown-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b = SigningKey::from_bytes(&[9_u8; 32]);
    let runtime = vote_runtime(&directory, &key, &node_b);
    let (ca, server_id, _) = issue_identities();
    let server_config = server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca])
        .expect("server config");
    let server =
        ProductionWitnessServer::bind(membership(), server_config, runtime, Duration::from_secs(1))
            .expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || server.serve_until(&shutdown_clone));

    let mut idle = connect_retry(listen_addr).expect("idle connect");
    idle.set_read_timeout(Some(Duration::from_millis(100)))
        .expect("read timeout");
    shutdown.request();
    assert!(server_thread.join().expect("server thread").is_ok());

    let mut byte = [0_u8; 1];
    let closed = idle.read(&mut byte);
    let closed_by_server = match closed {
        Ok(0) => true,
        Err(error) => matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::NotConnected
        ),
        Ok(_) => false,
    };
    assert!(closed_by_server);
    let _ = idle.shutdown(Shutdown::Both);
    let _ = fs::remove_dir_all(directory);
}
