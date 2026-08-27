#![allow(clippy::expect_used)]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use quorumarc_service::adapters::{
    AdapterError, ClosedOnlyEffectAdapter, EffectAdapter, MockEffectAdapter,
};
use quorumarc_service::config::ProductionConfig;
use quorumarc_service::node::{DaemonReadiness, ProductionNode};
use quorumarc_service::operations::{NodeStatusReport, StatusHandle};
use quorumarc_service::reload::run_reload_loop;
use quorumarc_service::signal::ShutdownToken;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const VALID_PRODUCTION: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.23:7602"
store_dir = "/var/lib/quorumarc/authority"
signing_key = "/etc/quorumarc/node-a.seed"
automatic_promotion = true

[tls]
certificate_chain = "/etc/quorumarc/tls/node-a.crt"
private_key = "/etc/quorumarc/tls/node-a.key"
trusted_roots = "/etc/quorumarc/tls/ca.crt"
server_name = "witness.example.internal"
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
[[members]]
id = "node-b"
role = "data"
address = "172.30.1.21:7601"
failure_domain = "power-b"
[[members]]
id = "witness-a"
role = "witness"
address = "172.30.1.23:7602"
failure_domain = "power-w"
"#;

#[test]
fn incomplete_production_node_never_reports_ready_or_opens_effects() {
    let node = ProductionNode::effect_closed();
    assert_eq!(node.readiness(), DaemonReadiness::EffectClosed);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}

#[test]
fn shutdown_wait_blocks_until_request_and_then_unblocks() {
    let shutdown = ShutdownToken::new();
    let worker = shutdown.clone();
    let handle = thread::spawn(move || worker.wait());
    thread::sleep(Duration::from_millis(10));
    assert!(!handle.is_finished());
    shutdown.request();
    handle.join().expect("wait thread");
}

#[test]
fn config_reload_loop_swaps_log_level_and_refuses_unsafe_changes() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-reload-loop-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("agent.toml");
    fs::write(&path, VALID_PRODUCTION).expect("write");
    let active = ProductionConfig::parse(VALID_PRODUCTION).expect("parse");
    let status = StatusHandle::new(NodeStatusReport::new(&active, "boot", 1, None));
    let shutdown = ShutdownToken::new();
    let reload = shutdown.reload_token();
    let worker_path = path.clone();
    let worker_status = status.clone();
    let worker_reload = reload.clone();
    let handle = thread::spawn(move || {
        run_reload_loop(
            &worker_path,
            active,
            "data",
            &worker_status,
            "boot",
            || 1,
            &worker_reload,
        );
    });

    fs::write(
        &path,
        VALID_PRODUCTION.replace(
            "automatic_promotion = true",
            "automatic_promotion = true\nlog_level = \"debug\"",
        ),
    )
    .expect("debug");
    reload.request();
    wait_until(|| snapshot(&status).log_level() == "debug");
    assert_eq!(snapshot(&status).cluster_id(), "prod-cluster");
    assert_eq!(snapshot(&status).effect_gate(), "closed");

    fs::write(
        &path,
        VALID_PRODUCTION.replace("cluster_id = \"prod-cluster\"", "cluster_id = \"other\""),
    )
    .expect("unsafe");
    reload.request();
    thread::sleep(Duration::from_millis(50));
    assert_eq!(snapshot(&status).log_level(), "debug");
    assert_eq!(snapshot(&status).cluster_id(), "prod-cluster");
    assert_eq!(snapshot(&status).effect_gate(), "closed");

    shutdown.request();
    handle.join().expect("reload loop");
    let _ = fs::remove_dir_all(directory);
}

fn snapshot(status: &StatusHandle) -> NodeStatusReport {
    status.snapshot().expect("status")
}

fn wait_until(predicate: impl Fn() -> bool) {
    for _ in 0..50 {
        if predicate() {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(predicate(), "condition never became true");
}

#[test]
fn reload_wait_wakes_on_request_and_cancels_on_shutdown() {
    let shutdown = ShutdownToken::new();
    let reload = shutdown.reload_token();
    let worker_reload = reload.clone();
    let handle = thread::spawn(move || worker_reload.wait_after(0));
    thread::sleep(Duration::from_millis(10));
    assert!(!handle.is_finished());
    reload.request();
    assert_eq!(handle.join().expect("reload thread"), Some(1));

    let worker_reload = reload.clone();
    let handle = thread::spawn(move || worker_reload.wait_after(1));
    thread::sleep(Duration::from_millis(10));
    assert!(!handle.is_finished());
    shutdown.request();
    assert_eq!(handle.join().expect("shutdown reload thread"), None);
}

#[test]
fn watchdog_pings_running_daemon_and_never_emits_ready() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-watchdog-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let notify_socket = directory.join("notify.sock");
    let listener = std::os::unix::net::UnixDatagram::bind(&notify_socket).expect("bind notify");
    listener
        .set_read_timeout(Some(Duration::from_millis(100)))
        .expect("timeout");

    let watchdog = quorumarc_service::watchdog::SystemdWatchdog::from_socket_path(
        &notify_socket,
        Duration::from_millis(20),
    )
    .expect("watchdog");
    assert!(!watchdog.emitted_ready());

    let shutdown = ShutdownToken::new();
    let worker_shutdown = shutdown.clone();
    let handle = thread::spawn(move || watchdog.run_until(&worker_shutdown));

    let mut buf = [0_u8; 128];
    let (len, _) = listener.recv_from(&mut buf).expect("first ping");
    let first = std::str::from_utf8(&buf[..len]).expect("utf8");
    assert_eq!(first.trim(), "WATCHDOG=1");
    assert!(!first.contains("READY=1"));

    shutdown.request();
    handle.join().expect("watchdog stop");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn watchdog_detects_half_interval_from_systemd_environment() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-watchdog-env-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let notify_socket = directory.join("notify.sock");
    std::os::unix::net::UnixDatagram::bind(&notify_socket).expect("bind notify");

    let watchdog = quorumarc_service::watchdog::SystemdWatchdog::from_environment_variables(
        Some(notify_socket.to_str().expect("utf8")),
        Some("2000000"),
    )
    .expect("env watchdog")
    .expect("some watchdog");
    assert_eq!(watchdog.interval(), Duration::from_secs(1));
    assert!(
        quorumarc_service::watchdog::SystemdWatchdog::from_environment_variables(None, None)
            .is_ok_and(|watchdog| watchdog.is_none())
    );
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_node_refuses_open_effect_adapter() {
    let mut adapter = MockEffectAdapter::closed();
    adapter
        .open_with_receipt("orders-api", 2, [11; 32])
        .expect("open");
    assert!(matches!(
        ProductionNode::from_effect_adapter(&adapter),
        Err(AdapterError::EffectNotClosed)
    ));
    ClosedOnlyEffectAdapter
        .verify_closed()
        .expect("production default remains closed");
    ProductionNode::from_effect_adapter(&ClosedOnlyEffectAdapter)
        .expect("closed-only adapter may start");
}

#[test]
fn effect_closed_daemon_stops_without_ever_becoming_ready() {
    let mut node = ProductionNode::effect_closed();
    let shutdown = ShutdownToken::new();
    shutdown.request();
    let report = node.run_until_shutdown(&shutdown);
    assert_eq!(report.initial, DaemonReadiness::EffectClosed);
    assert_eq!(report.final_state, DaemonReadiness::Stopped);
    assert!(!report.ever_ready);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}
