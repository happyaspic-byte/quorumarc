#![allow(clippy::expect_used)]

use std::fs;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use quorumarc_service::adapters::{
    AdapterError, ClosedOnlyEffectAdapter, EffectAdapter, MockEffectAdapter,
};
use quorumarc_service::candidate_loop::{
    CandidateAttempt, CandidateControlLoop, CandidateControlState, CandidateFailure,
};
use quorumarc_service::config::ProductionConfig;
use quorumarc_service::node::{DaemonReadiness, ProductionNode};
use quorumarc_service::operations::{NodeStatusReport, StatusHandle};
use quorumarc_service::protocol::{ProductionRequest, ProductionVotePayload};
use quorumarc_service::reload::run_reload_loop;
use quorumarc_service::signal::ShutdownToken;
use quorumarc_service::witness_client::{CandidateControlError, WitnessClientError};
use quorumarc_wire::ProductionQuorumCertificate;

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
store_id = "07070707070707070707070707070707"
signing_key = "/etc/quorumarc/node-a.seed"
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
address = "172.30.1.23:7602"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "/etc/quorumarc/keys/witness-a.pub"
"#;

struct RecordingCandidate {
    results: Vec<Result<ProductionQuorumCertificate, CandidateControlError>>,
    requests: Arc<AtomicUsize>,
}

impl CandidateAttempt for RecordingCandidate {
    fn request_certificate(
        &mut self,
        _request: ProductionRequest,
    ) -> Result<ProductionQuorumCertificate, CandidateControlError> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.results.pop().map_or_else(
            || {
                Err(CandidateControlError::Witness(
                    WitnessClientError::Malformed,
                ))
            },
            |result| result,
        )
    }
}

fn candidate_request() -> ProductionRequest {
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
        payload: ProductionVotePayload::new([31; 32], 12, 10_000, 14_000)
            .expect("payload")
            .encode(),
    }
}

#[test]
fn candidate_loop_requests_certificate_only_for_explicit_suspicion() {
    let requests = Arc::new(AtomicUsize::new(0));
    let control = RecordingCandidate {
        results: vec![Err(CandidateControlError::Witness(
            WitnessClientError::Transport,
        ))],
        requests: Arc::clone(&requests),
    };
    let mut candidate = CandidateControlLoop::new(control);

    assert_eq!(
        candidate.handle(CandidateFailure::Malformed, candidate_request()),
        CandidateControlState::EffectClosed
    );
    assert_eq!(
        candidate.handle(CandidateFailure::AuthenticationFailed, candidate_request()),
        CandidateControlState::EffectClosed
    );
    assert_eq!(requests.load(Ordering::Relaxed), 0);

    assert_eq!(
        candidate.handle(CandidateFailure::NodeFailureSuspicion, candidate_request()),
        CandidateControlState::SuspicionEffectClosed
    );
    assert_eq!(requests.load(Ordering::Relaxed), 1);
    assert_eq!(candidate.effect_gate_state(), "closed");
}

#[test]
fn candidate_loop_bounds_transport_retry_and_obeys_shutdown() {
    let requests = Arc::new(AtomicUsize::new(0));
    let control = RecordingCandidate {
        results: vec![
            Err(CandidateControlError::Witness(
                WitnessClientError::Transport,
            )),
            Err(CandidateControlError::Witness(
                WitnessClientError::Transport,
            )),
            Err(CandidateControlError::Witness(
                WitnessClientError::Transport,
            )),
        ],
        requests: Arc::clone(&requests),
    };
    let mut candidate = CandidateControlLoop::new(control);
    let shutdown = ShutdownToken::new();

    let state = candidate.run_bounded(
        CandidateFailure::NodeFailureSuspicion,
        candidate_request(),
        &shutdown,
    );
    assert_eq!(state, CandidateControlState::SuspicionEffectClosed);
    assert_eq!(
        requests.load(Ordering::Relaxed),
        CandidateControlLoop::<RecordingCandidate>::MAX_ATTEMPTS
    );

    shutdown.request();
    let before_shutdown = requests.load(Ordering::Relaxed);
    let state = candidate.run_bounded(
        CandidateFailure::NodeFailureSuspicion,
        candidate_request(),
        &shutdown,
    );
    assert_eq!(state, CandidateControlState::StoppedEffectClosed);
    assert_eq!(requests.load(Ordering::Relaxed), before_shutdown);
}

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
fn watchdog_pings_systemd_abstract_notify_socket_and_never_emits_ready() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let name = format!(
        "quorumarc-notify-{}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    );
    let addr = SocketAddr::from_abstract_name(name.as_bytes()).expect("abstract name");
    let listener = UnixDatagram::bind_addr(&addr).expect("bind abstract");
    listener
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("timeout");

    let notify = format!("@{name}");
    let watchdog = quorumarc_service::watchdog::SystemdWatchdog::from_environment_variables(
        Some(&notify),
        Some("400000"),
    )
    .expect("env watchdog")
    .expect("some watchdog");
    assert!(!watchdog.emitted_ready());
    assert_eq!(watchdog.interval(), Duration::from_millis(200));

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
