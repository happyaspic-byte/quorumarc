#![allow(clippy::expect_used)]

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::Arc;
use std::thread;

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConnection, ServerConnection, StreamOwned};

use quorumarc_service::tls::{
    TlsMaterialError, client_mtls_config, load_mtls_client_config, load_mtls_server_config,
    server_mtls_config,
};

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

fn issue_pem_identities() -> (String, String, String, String, String) {
    let mut ca_params = CertificateParams::new(vec!["quorumarc-ca".to_owned()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca");

    let mut server_params =
        CertificateParams::new(vec!["witness.test".to_owned()]).expect("server");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server cert");

    let mut client_params = CertificateParams::new(vec!["node-a.test".to_owned()]).expect("client");
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().expect("client key");
    let client = client_params
        .signed_by(&client_key, &ca, &ca_key)
        .expect("client cert");
    (
        ca.pem(),
        server.pem(),
        server_key.serialize_pem(),
        client.pem(),
        client_key.serialize_pem(),
    )
}

#[test]
fn production_tls_file_loader_requires_safe_bounded_material_and_builds_mtls() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-tls-files-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let (ca, server_cert, server_key, client_cert, client_key) = issue_pem_identities();
    let ca_path = directory.join("ca.pem");
    let server_cert_path = directory.join("server.pem");
    let server_key_path = directory.join("server-key.pem");
    let client_cert_path = directory.join("client.pem");
    let client_key_path = directory.join("client-key.pem");
    fs::write(&ca_path, ca).expect("ca");
    fs::write(&server_cert_path, server_cert).expect("server cert");
    fs::write(&server_key_path, server_key).expect("server key");
    fs::write(&client_cert_path, client_cert).expect("client cert");
    fs::write(&client_key_path, client_key).expect("client key");
    fs::set_permissions(&server_key_path, fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::set_permissions(&client_key_path, fs::Permissions::from_mode(0o600)).expect("chmod");

    let server = load_mtls_server_config(&server_cert_path, &server_key_path, &ca_path)
        .expect("server config");
    let client = load_mtls_client_config(&client_cert_path, &client_key_path, &ca_path)
        .expect("client config");
    assert!(server.into_server_config().alpn_protocols.is_empty());
    assert!(client.alpn_protocols.is_empty());

    fs::set_permissions(&server_key_path, fs::Permissions::from_mode(0o640)).expect("chmod unsafe");
    assert!(matches!(
        load_mtls_server_config(&server_cert_path, &server_key_path, &ca_path),
        Err(TlsMaterialError::UnsafePrivateKey)
    ));
    fs::set_permissions(&server_key_path, fs::Permissions::from_mode(0o600)).expect("chmod safe");

    let symlink_path = directory.join("symlink-key.pem");
    symlink(&server_key_path, &symlink_path).expect("symlink");
    assert!(matches!(
        load_mtls_server_config(&server_cert_path, &symlink_path, &ca_path),
        Err(TlsMaterialError::UnsafePrivateKey)
    ));

    let oversized = directory.join("oversized.pem");
    fs::write(&oversized, vec![b'A'; 1_048_577]).expect("oversized");
    assert!(matches!(
        load_mtls_server_config(&oversized, &server_key_path, &ca_path),
        Err(TlsMaterialError::MaterialTooLarge)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_transport_completes_only_with_mutually_trusted_certificates() {
    let (ca, server, client) = issue_identities();
    let server_config = server_mtls_config(vec![server.certificate], server.key, vec![ca.clone()])
        .expect("server config");
    let client_config =
        client_mtls_config(vec![client.certificate], client.key, vec![ca]).expect("client config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");

    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let connection = ServerConnection::new(Arc::new(server_config.into_server_config()))
            .expect("server TLS");
        let mut tls = StreamOwned::new(connection, stream);
        let mut request = [0_u8; 4];
        tls.read_exact(&mut request).expect("authenticated read");
        assert_eq!(&request, b"vote");
        tls.write_all(b"grant").expect("authenticated write");
    });

    let stream = TcpStream::connect(address).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    tls.write_all(b"vote").expect("write");
    let mut response = [0_u8; 5];
    tls.read_exact(&mut response).expect("read");
    assert_eq!(&response, b"grant");
    server_thread.join().expect("server thread");
}

#[test]
fn production_transport_refuses_client_without_trusted_certificate() {
    let (trusted_ca, server, _) = issue_identities();
    let (_, _, untrusted_client) = issue_identities();
    let server_config = server_mtls_config(
        vec![server.certificate],
        server.key,
        vec![trusted_ca.clone()],
    )
    .expect("server config");
    let client_config = client_mtls_config(
        vec![untrusted_client.certificate],
        untrusted_client.key,
        vec![trusted_ca],
    )
    .expect("client config");
    let listener = TcpListener::bind("127.0.0.1:0").expect("listen");
    let address = listener.local_addr().expect("address");

    let server_thread = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let connection = ServerConnection::new(Arc::new(server_config.into_server_config()))
            .expect("server TLS");
        let mut tls = StreamOwned::new(connection, stream);
        let mut request = [0_u8; 4];
        assert!(tls.read_exact(&mut request).is_err());
    });

    let stream = TcpStream::connect(address).expect("connect");
    let server_name = ServerName::try_from("witness.test").expect("server name");
    let connection =
        ClientConnection::new(Arc::new(client_config), server_name).expect("client TLS");
    let mut tls = StreamOwned::new(connection, stream);
    let write_result = tls.write_all(b"vote");
    let mut response = [0_u8; 1];
    assert!(write_result.is_err() || tls.read_exact(&mut response).is_err());
    server_thread.join().expect("server thread");
}
