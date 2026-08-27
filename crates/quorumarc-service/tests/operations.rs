#![allow(clippy::expect_used)]

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use quorumarc_service::config::ProductionConfig;
use quorumarc_service::operations::{
    LocalStatusServer, NodeStatusReport, SupportBundle, export_support_bundle,
};

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

const SAMPLE_CONFIG: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.200:7602"
store_dir = "/var/lib/quorumarc/authority"
store_id = "07070707070707070707070707070707"
signing_key = "/etc/quorumarc/secrets/node-a.seed"
key_id = "node-a-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = true

[tls]
certificate_chain = "/etc/quorumarc/tls/node-a.crt"
private_key = "/etc/quorumarc/tls/node-a.key"
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
fn node_status_report_reflects_closed_effect_gate_and_boot_identity() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    assert_eq!(status.cluster_id(), "prod-cluster");
    assert_eq!(status.node_id(), "node-a");
    assert_eq!(status.effect_gate(), "closed");
    assert!(!status.authority_enabled());
    assert_eq!(status.boot_id(), "mock-boot-id-001");
    assert_eq!(status.uptime_ms(), 123_456);
    assert_eq!(status.last_committed_index(), Some(42));
    assert_eq!(status.log_level(), "info");
}

#[test]
fn unknown_commit_index_is_serialized_as_null_not_zero() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, None);
    assert_eq!(status.last_committed_index(), None);
    let bundle = export_support_bundle(&config, "mock-boot-id-001", 123_456, None);
    assert!(
        bundle
            .manifest_json()
            .contains("\"last_committed_index\":null")
    );
    assert!(
        !bundle
            .manifest_json()
            .contains("\"last_committed_index\":0")
    );
}

#[test]
fn support_bundle_redacts_private_keys_and_preserves_cluster_manifest() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let bundle: SupportBundle =
        export_support_bundle(&config, "mock-boot-id-001", 123_456, Some(42));
    assert!(
        !bundle
            .manifest_json()
            .contains("/etc/quorumarc/secrets/node-a.seed")
    );
    assert!(
        bundle
            .manifest_json()
            .contains("<REDACTED_PRIVATE_KEY_PATH>")
    );
    assert!(
        bundle
            .manifest_json()
            .contains("\"effect_gate\":\"closed\"")
    );
    assert_eq!(bundle.cluster_id(), "prod-cluster");
    assert_eq!(bundle.members_count(), 3);
    assert_ne!(bundle.bundle_digest(), [0; 32]);
}

#[test]
fn support_bundle_records_fence_and_membership_state() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let bundle = export_support_bundle(&config, "mock-boot-id-001", 123_456, Some(42));
    assert_eq!(bundle.fence_mechanism(), "hardware-power");
    assert_eq!(bundle.fence_profile(), "pdu-a");
    assert!(bundle.fence_read_back());
    assert!(
        bundle
            .manifest_json()
            .contains("\"fence_mechanism\":\"hardware-power\"")
    );
    assert!(bundle.manifest_json().contains("\"members_count\":3"));
    assert!(!bundle.manifest_json().contains("172.30.1.84"));
}

#[test]
fn support_bundle_escapes_untrusted_manifest_fields() {
    let config_text = SAMPLE_CONFIG.replace("prod-cluster", "prod\\\"cluster");
    let config = ProductionConfig::parse(&config_text).expect("valid escaped config");
    let bundle = export_support_bundle(&config, "boot\\\"id", 1, None);
    assert!(bundle.manifest_json().contains("prod\\\"cluster"));
    assert!(bundle.manifest_json().contains("boot\\\\\\\"id"));
    assert!(
        !bundle
            .manifest_json()
            .contains("\"cluster_id\":\"prod\"cluster\"")
    );
}

#[test]
fn local_status_socket_refuses_existing_path_without_deleting_it() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "quorumarc-status-existing-{}-{sequence}.sock",
        std::process::id()
    ));
    std::fs::write(&path, b"operator-owned").expect("sentinel");
    assert!(LocalStatusServer::bind(&path, status).is_err());
    assert_eq!(
        std::fs::read(&path).expect("sentinel retained"),
        b"operator-owned"
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn local_status_socket_does_not_unlink_replacement_path_after_serving() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = std::env::temp_dir().join(format!(
        "quorumarc-status-replaced-{}-{sequence}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let server = LocalStatusServer::bind(&socket, status).expect("bind");
    let mut client = UnixStream::connect(&socket).expect("connect");
    std::fs::remove_file(&socket).expect("unlink live socket name");
    std::fs::write(&socket, b"operator-replacement").expect("replacement");
    let handle = thread::spawn(move || server.serve_one());
    client.write_all(b"STATUS\n").expect("write request");
    let mut body = String::new();
    client.read_to_string(&mut body).expect("read status");
    handle.join().expect("join").expect("serve");
    assert_eq!(
        std::fs::read(&socket).expect("replacement retained"),
        b"operator-replacement"
    );
    let _ = std::fs::remove_file(socket);
}

#[test]
fn local_status_socket_does_not_unlink_replacement_socket_after_serving() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = std::env::temp_dir().join(format!(
        "quorumarc-status-replaced-socket-{}-{sequence}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let server = LocalStatusServer::bind(&socket, status).expect("bind");
    let mut client = UnixStream::connect(&socket).expect("connect");
    std::fs::remove_file(&socket).expect("unlink live socket name");
    let replacement = std::os::unix::net::UnixListener::bind(&socket).expect("replacement socket");
    let handle = thread::spawn(move || server.serve_one());
    client.write_all(b"STATUS\n").expect("write request");
    let mut body = String::new();
    client.read_to_string(&mut body).expect("read status");
    handle.join().expect("join").expect("serve");
    assert!(socket.exists());
    drop(replacement);
    let _ = std::fs::remove_file(socket);
}

#[test]
fn local_status_socket_is_read_only_and_cannot_open_effects() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = std::env::temp_dir().join(format!(
        "quorumarc-status-{}-{sequence}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let server = LocalStatusServer::bind(&socket, status).expect("bind");
    let handle = thread::spawn(move || server.serve_one());
    thread::sleep(Duration::from_millis(20));
    let mut client = UnixStream::connect(&socket).expect("connect");
    client
        .write_all(b"PROMOTE\nACTIVATE\n")
        .expect("write mutation");
    let mut body = String::new();
    client.read_to_string(&mut body).expect("read status");
    handle.join().expect("join").expect("serve");
    let _ = std::fs::remove_file(&socket);
    assert!(body.contains("\"effect_gate\":\"closed\""));
    assert!(body.contains("\"authority_enabled\":false"));
    assert!(body.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(!body.contains("PROMOTE"));
    assert!(!body.contains("ACTIVATE"));
}

#[test]
fn local_status_socket_survives_peer_close_before_response() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = std::env::temp_dir().join(format!(
        "quorumarc-status-peer-close-{}-{sequence}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let server = LocalStatusServer::bind(&socket, status).expect("bind");
    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));
    drop(UnixStream::connect(&socket).expect("peer close connect"));
    thread::sleep(Duration::from_millis(20));
    let mut client = UnixStream::connect(&socket).expect("second connect");
    client.write_all(b"STATUS\n").expect("write");
    let mut body = String::new();
    client.read_to_string(&mut body).expect("read");
    assert!(body.contains("\"effect_gate\":\"closed\""));
    shutdown.request();
    handle.join().expect("join").expect("serve");
}

#[test]
fn local_status_socket_serves_two_clients_then_unlinks_owned_path() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let status = NodeStatusReport::new(&config, "mock-boot-id-001", 123_456, Some(42));
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    let socket = std::env::temp_dir().join(format!(
        "quorumarc-status-loop-{}-{sequence}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let server = LocalStatusServer::bind(&socket, status).expect("bind");
    let shutdown = quorumarc_service::signal::ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || server.serve_until(&worker_shutdown));
    thread::sleep(Duration::from_millis(20));
    for _ in 0..2 {
        let mut client = UnixStream::connect(&socket).expect("connect");
        client.write_all(b"STATUS\n").expect("write");
        let mut body = String::new();
        client.read_to_string(&mut body).expect("read");
        assert!(body.contains("\"effect_gate\":\"closed\""));
    }
    shutdown.request();
    handle.join().expect("join").expect("serve");
    assert!(!socket.exists());
}
