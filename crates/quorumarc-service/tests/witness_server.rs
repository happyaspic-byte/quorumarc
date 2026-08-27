#![allow(clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, StreamOwned};

use quorumarc_service::protocol::{ProductionFrame, ProductionFrameKind, ProductionRequest};
use quorumarc_service::signal::ShutdownToken;
use quorumarc_service::tls::{client_mtls_config, server_mtls_config};
use quorumarc_service::witness::{ProductionWitnessRuntime, ProductionWitnessServer};

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
            epoch: 4,
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
fn production_witness_server_serves_authenticated_votes_over_mtls() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-witness-server-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let runtime = ProductionWitnessRuntime::open(
        &directory,
        [41; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("open");
    assert!(!runtime.effects_open());

    let (ca, server_id, client_id) = issue_identities();
    let server_config =
        server_mtls_config(vec![server_id.certificate], server_id.key, vec![ca.clone()])
            .expect("server config");
    let client_config = client_mtls_config(vec![client_id.certificate], client_id.key, vec![ca])
        .expect("client config");

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let server = ProductionWitnessServer::bind(bind_addr, server_config, runtime).expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || {
        server.serve_until(&shutdown_clone).expect("serve");
    });

    let first = signed_request(1, [11; 16], b"vote", &key);
    let stream = connect_retry(listen_addr).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config.clone()), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    write_frame(&mut tls, &first);
    assert_eq!(read_status(&mut tls), b"COMMITTED\n");

    let stream2 = connect_retry(listen_addr).expect("connect 2");
    let server_name2 = ServerName::try_from("witness.test").expect("server name");
    let connection2 =
        ClientConnection::new(Arc::new(client_config), server_name2).expect("client TLS 2");
    let mut tls2 = StreamOwned::new(connection2, stream2);
    write_frame(&mut tls2, &first);
    assert_eq!(read_status(&mut tls2), b"ALREADY_DURABLE\n");

    shutdown.request();
    server_thread.join().expect("server thread");

    let resumed = ProductionWitnessRuntime::open(
        &directory,
        [41; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("resume");
    assert!(!resumed.effects_open());
    assert_eq!(resumed.highest_sequence(), 1);
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
    let runtime = ProductionWitnessRuntime::open(
        &directory,
        [42; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("open");

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

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("addr");
    let server = ProductionWitnessServer::bind(bind_addr, server_config, runtime).expect("bind");
    let listen_addr = server.local_addr().expect("local addr");
    let shutdown = ShutdownToken::new();
    let shutdown_clone = shutdown.clone();
    let server_thread = thread::spawn(move || {
        server.serve_until(&shutdown_clone).expect("serve");
    });

    let first = signed_request(1, [11; 16], b"vote", &key);
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

    let resumed = ProductionWitnessRuntime::open(
        &directory,
        [42; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("resume");
    assert_eq!(resumed.highest_sequence(), 0);
    assert!(!resumed.effects_open());
    let _ = fs::remove_dir_all(directory);
}
