#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use quorumarc_service::protocol::{
    ProductionFrame, ProductionFrameKind, ProductionRequest, ProductionVotePayload,
};
use quorumarc_service::tls::load_mtls_client_config;
use quorumarc_service::witness::ProductionVoteReply;
use quorumarc_wire::SigningKey;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, StreamOwned};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const WITNESS_CONFIG: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "witness-a"
workload_id = "orders-api"
role = "witness"
listen = "172.30.1.200:7602"
witness = "172.30.1.200:7602"
store_dir = "/var/lib/quorumarc-witness/control"
store_id = "09090909090909090909090909090909"
signing_key = "/etc/quorumarc/secrets/witness-a.seed"
key_id = "witness-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = false

[tls]
certificate_chain = "/etc/quorumarc/tls/witness-a.crt"
private_key = "/etc/quorumarc/tls/witness-a.key"
trusted_roots = "/etc/quorumarc/tls/ca.crt"
server_name = "witness.example.internal"
io_timeout_ms = 5000
[fence]
mechanism = "hardware-power"
profile = "pdu-a"
read_back = true
[workload]
unit = "orders-api.service"
[effect]
vip = "172.30.1.100/24"
interface = "enp1s0"
[[members]]
id = "node-a"
role = "data"
address = "172.30.1.22:7601"
failure_domain = "power-a"
key_id = "node-a-2026-01"
public_key = "/etc/quorumarc/keys/node-a.pub"
[[members]]
id = "node-b"
role = "data"
address = "172.30.1.21:7601"
failure_domain = "power-b"
key_id = "node-b-2026-01"
public_key = "/etc/quorumarc/keys/node-b.pub"
[[members]]
id = "witness-a"
role = "witness"
address = "172.30.1.200:7602"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "/etc/quorumarc/keys/witness-a.pub"
"#;

#[test]
fn production_witness_daemon_serves_tls_listener_until_sigterm() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-daemon-tls-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let (config_text, listen_addr) = witness_config_with_prerequisites(&directory)?;
    let config = directory.join("witness.toml");
    fs::write(&config, config_text)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_tcp(listen_addr, &mut child)?;
    assert!(child.try_wait()?.is_none());

    let client_config = load_mtls_client_config(
        &directory.join("node-a.crt"),
        &directory.join("node-a.key"),
        &directory.join("ca.crt"),
    )
    .map_err(|error| format!("client TLS: {error:?}"))?;
    let stream = TcpStream::connect(listen_addr)?;
    let connection = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("witness.test")?,
    )?;
    let mut tls = StreamOwned::new(connection, stream);
    let node_a = SigningKey::from_bytes(&[7_u8; 32]);
    let payload = ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)?.encode();
    let frame = ProductionFrame::sign(
        ProductionFrameKind::Request,
        ProductionRequest {
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
            payload,
        },
        &node_a,
    )?
    .encode()?;
    tls.write_all(&u32::try_from(frame.len())?.to_be_bytes())?;
    tls.write_all(&frame)?;
    tls.flush()?;
    let mut length = [0_u8; 4];
    tls.read_exact(&mut length)?;
    let mut response = vec![0_u8; u32::from_be_bytes(length) as usize];
    tls.read_exact(&mut response)?;
    let reply =
        ProductionVoteReply::decode(&response).map_err(|error| format!("vote reply: {error:?}"))?;
    assert!(reply.is_granted());
    assert_eq!(reply.cluster_id(), "prod-cluster");
    assert_eq!(
        reply
            .signed_vote()
            .expect("signed vote")
            .cluster_id()
            .as_str(),
        "prod-cluster"
    );

    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "stderr={stderr}");
    assert!(stdout.contains("WITNESS_DAEMON_STOPPED_VOTING"));
    assert!(stdout.contains("effect_gate=closed"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_witness_daemon_handles_sighup_reload_and_stops_on_sigterm()
-> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-reload-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("witness.toml");
    let (config_text, _) = witness_config_with_prerequisites(&directory)?;
    fs::write(&config, &config_text)?;
    let socket = directory.join("status.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut child)?;
    let initial = read_status(&socket)?;
    assert!(initial.contains("\"log_level\":\"info\""));
    assert!(initial.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(initial.contains("\"effect_gate\":\"closed\""));

    fs::write(
        &config,
        config_text.replace(
            "automatic_promotion = false",
            "automatic_promotion = false\nlog_level = \"debug\"",
        ),
    )?;
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let reloaded = wait_for_status(&socket, "\"log_level\":\"debug\"")?;
    assert!(reloaded.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(reloaded.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    fs::write(
        &config,
        config_text
            .replace(
                "automatic_promotion = false",
                "automatic_promotion = false\nlog_level = \"debug\"",
            )
            .replace("cluster_id = \"prod-cluster\"", "cluster_id = \"other\""),
    )?;
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    thread::sleep(Duration::from_millis(200));
    let refused = read_status(&socket)?;
    assert!(refused.contains("\"log_level\":\"debug\""));
    assert!(refused.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(refused.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(stdout.contains("WITNESS_DAEMON_STOPPED_VOTING"));
    assert!(stdout.contains("effect_gate=closed"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_witness_daemon_refuses_second_process_on_the_same_store() -> Result<(), Box<dyn Error>>
{
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-owner-lock-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("witness.toml");
    let (config_text, _) = witness_config_with_prerequisites(&directory)?;
    fs::write(&config, config_text)?;

    let mut first = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    thread::sleep(Duration::from_millis(100));
    assert!(first.try_wait()?.is_none());

    let second = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8(second.stderr)?;
    assert!(!second.status.success());
    assert!(stderr.contains("OWNER_LOCK_REFUSED"));
    assert!(stderr.contains("effect_gate=closed"));
    assert!(first.try_wait()?.is_none());

    assert!(
        Command::new("kill")
            .args(["-TERM", &first.id().to_string()])
            .status()?
            .success()
    );
    let output = first.wait_with_output()?;
    assert!(output.status.success());
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

fn witness_config_with_prerequisites(
    directory: &std::path::Path,
) -> Result<(String, std::net::SocketAddr), Box<dyn Error>> {
    let store = directory.join("store");
    let key = directory.join("witness.seed");
    fs::create_dir_all(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;

    let witness_signing = SigningKey::from_bytes(&[29_u8; 32]);
    let node_a_signing = SigningKey::from_bytes(&[7_u8; 32]);
    let node_b_signing = SigningKey::from_bytes(&[9_u8; 32]);
    write_private_file(&key, &witness_signing.to_bytes())?;

    let witness_pub = directory.join("witness.pub");
    let node_a_pub = directory.join("node-a.pub");
    let node_b_pub = directory.join("node-b.pub");
    fs::write(&witness_pub, witness_signing.verifying_key().to_bytes())?;
    fs::write(&node_a_pub, node_a_signing.verifying_key().to_bytes())?;
    fs::write(&node_b_pub, node_b_signing.verifying_key().to_bytes())?;

    let material = issue_tls_material()?;
    let cert_path = directory.join("witness.crt");
    let tls_key_path = directory.join("witness.key");
    let client_cert_path = directory.join("node-a.crt");
    let client_key_path = directory.join("node-a.key");
    let ca_path = directory.join("ca.crt");
    fs::write(&cert_path, material.server_cert)?;
    write_private_file(&tls_key_path, material.server_key.as_bytes())?;
    fs::write(client_cert_path, material.client_cert)?;
    write_private_file(&client_key_path, material.client_key.as_bytes())?;
    fs::write(&ca_path, material.ca_cert)?;

    let probe_listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let listen_addr = probe_listener.local_addr()?;
    drop(probe_listener);

    let text = WITNESS_CONFIG
        .replace(
            "/var/lib/quorumarc-witness/control",
            store.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/secrets/witness-a.seed",
            key.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/tls/witness-a.crt",
            cert_path.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/tls/witness-a.key",
            tls_key_path.to_str().ok_or("utf8")?,
        )
        .replace("/etc/quorumarc/tls/ca.crt", ca_path.to_str().ok_or("utf8")?)
        .replace(
            "server_name = \"witness.example.internal\"",
            "server_name = \"witness.test\"",
        )
        .replace(
            "/etc/quorumarc/keys/node-a.pub",
            node_a_pub.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/keys/node-b.pub",
            node_b_pub.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/keys/witness-a.pub",
            witness_pub.to_str().ok_or("utf8")?,
        )
        .replace("172.30.1.200:7602", &listen_addr.to_string())
        .replace("172.30.1.22:7601", "127.0.0.2:7601")
        .replace("172.30.1.21:7601", "127.0.0.3:7601");
    Ok((text, listen_addr))
}

fn write_private_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

struct TlsFixtureMaterial {
    server_cert: String,
    server_key: String,
    client_cert: String,
    client_key: String,
    ca_cert: String,
}

fn issue_tls_material() -> Result<TlsFixtureMaterial, Box<dyn Error>> {
    let mut ca_params = CertificateParams::new(vec!["quorumarc-ca".to_owned()])?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate()?;
    let ca = ca_params.self_signed(&ca_key)?;
    let mut server_params = CertificateParams::new(vec!["witness.test".to_owned()])?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate()?;
    let server = server_params.signed_by(&server_key, &ca, &ca_key)?;
    let mut client_params = CertificateParams::new(vec!["node-a.test".to_owned()])?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate()?;
    let client = client_params.signed_by(&client_key, &ca, &ca_key)?;
    Ok(TlsFixtureMaterial {
        server_cert: server.pem(),
        server_key: server_key.serialize_pem(),
        client_cert: client.pem(),
        client_key: client_key.serialize_pem(),
        ca_cert: ca.pem(),
    })
}

fn wait_for_tcp(
    address: std::net::SocketAddr,
    child: &mut std::process::Child,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..50 {
        if child.try_wait()?.is_some() {
            return Err("daemon exited before tcp listener".into());
        }
        if TcpStream::connect(address).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("tcp listener was not created".into())
}

fn read_status(socket: &std::path::Path) -> Result<String, Box<dyn Error>> {
    let mut client = UnixStream::connect(socket)?;
    let mut body = String::new();
    client.read_to_string(&mut body)?;
    Ok(body)
}

fn wait_for_status(socket: &std::path::Path, needle: &str) -> Result<String, Box<dyn Error>> {
    for _ in 0..50 {
        if let Ok(body) = read_status(socket) {
            if body.contains(needle) {
                return Ok(body);
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("status never matched".into())
}

fn wait_for_socket(
    path: &std::path::Path,
    child: &mut std::process::Child,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..50 {
        if child.try_wait()?.is_some() {
            return Err("daemon exited before status socket".into());
        }
        if UnixStream::connect(path).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("status socket was not created".into())
}
