#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use quorumarc_cluster::{
    LifecycleAutoController, LifecycleAutoDecision, LifecycleAutoReason, LifecycleClient,
    LifecycleNodeId, LifecycleReasonCode, LifecycleState, lifecycle_lease, lifecycle_policy_hash,
};
use quorumarc_rpo0::{
    CounterOperation, FileReplica, OperationId, ReplicatedCounter, WalEntry, recover_wal,
};
use quorumarc_wire::SigningKey;

static NEXT: AtomicU64 = AtomicU64::new(1);
static PROCESS_LAB: Mutex<()> = Mutex::new(());
const TIMEOUT: Duration = Duration::from_secs(10);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const WITNESS_MAX_CONNECTIONS: usize = 16;
const PROXY_MAX_CONNECTIONS: usize = 16;

#[derive(Clone, Copy)]
enum WalMode {
    Expected,
    Empty,
    DifferentRoot,
}

#[derive(Clone, Copy)]
struct NodeSpec {
    wal: WalMode,
    policy_byte: u8,
    store_fault: &'static str,
}

impl NodeSpec {
    fn normal() -> Self {
        Self {
            wal: WalMode::Expected,
            policy_byte: lifecycle_policy_hash()[0],
            store_fault: "none",
        }
    }
}

struct Fixture {
    root: PathBuf,
    node_a_seed: PathBuf,
    node_b_seed: PathBuf,
    witness_seed: PathBuf,
    controller_seed: PathBuf,
    node_a_public: PathBuf,
    node_b_public: PathBuf,
    witness_public: PathBuf,
    controller_public: PathBuf,
    node_a_wal: PathBuf,
    node_b_wal: PathBuf,
}

impl Fixture {
    fn new(label: &str, node_a: NodeSpec, node_b: NodeSpec) -> Self {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "quorumarc-lifecycle-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create lifecycle fixture");
        let fixture = Self {
            node_a_seed: root.join("node-a.seed"),
            node_b_seed: root.join("node-b.seed"),
            witness_seed: root.join("witness.seed"),
            controller_seed: root.join("controller.seed"),
            node_a_public: root.join("node-a.public"),
            node_b_public: root.join("node-b.public"),
            witness_public: root.join("witness.public"),
            controller_public: root.join("controller.public"),
            node_a_wal: root.join("node-a.wal"),
            node_b_wal: root.join("node-b.wal"),
            root,
        };
        write_private(&fixture.node_a_seed, [11; 32]);
        write_private(&fixture.node_b_seed, [17; 32]);
        write_private(&fixture.witness_seed, [29; 32]);
        write_private(&fixture.controller_seed, [37; 32]);
        write_public(&fixture.node_a_public, [11; 32]);
        write_public(&fixture.node_b_public, [17; 32]);
        write_public(&fixture.witness_public, [29; 32]);
        write_public(&fixture.controller_public, [37; 32]);
        seed_acknowledged_write(&fixture.node_a_wal, &fixture.node_b_wal);
        apply_wal_mode(&fixture.node_a_wal, node_a.wal);
        apply_wal_mode(&fixture.node_b_wal, node_b.wal);
        fixture
    }
}

struct Lab {
    _process_lab_guard: MutexGuard<'static, ()>,
    fixture: Fixture,
    witness: Option<Child>,
    witness_address: SocketAddr,
    node_a_proxy: Option<Child>,
    node_b_proxy: Option<Child>,
    node_a_proxy_address: Option<SocketAddr>,
    node_b_proxy_address: Option<SocketAddr>,
    node_a_address: SocketAddr,
    node_b_address: SocketAddr,
    node_a: Option<Child>,
    node_b: Option<Child>,
    node_a_client: LifecycleClient,
    node_b_client: LifecycleClient,
}

impl Lab {
    fn start(label: &str, node_a_spec: NodeSpec, node_b_spec: NodeSpec) -> Self {
        Self::start_inner(label, node_a_spec, node_b_spec, false)
    }

    fn start_with_proxies(label: &str, node_a_spec: NodeSpec, node_b_spec: NodeSpec) -> Self {
        Self::start_inner(label, node_a_spec, node_b_spec, true)
    }

    fn start_inner(
        label: &str,
        node_a_spec: NodeSpec,
        node_b_spec: NodeSpec,
        with_proxies: bool,
    ) -> Self {
        // These tests intentionally start several real processes apiece. Rust's
        // default test parallelism can otherwise overload a shared CI runner
        // and turn scheduling delay into a false network timeout. The extended
        // campaign already uses one test thread; keep direct `cargo test`
        // equally deterministic within this process-test binary.
        let process_lab_guard = PROCESS_LAB
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let fixture = Fixture::new(label, node_a_spec, node_b_spec);
        let witness_ready = fixture.root.join("witness.ready");
        let mut witness = spawn_witness(&fixture, &witness_ready);
        let witness_address = wait_ready(&witness_ready, &mut witness);
        let (node_a_proxy, node_a_proxy_address) =
            start_proxy_if_requested(&fixture, "node-a", witness_address, with_proxies);
        let (node_b_proxy, node_b_proxy_address) =
            start_proxy_if_requested(&fixture, "node-b", witness_address, with_proxies);
        let node_a_ready = fixture.root.join("node-a.ready");
        let node_b_ready = fixture.root.join("node-b.ready");
        let mut node_a = spawn_node(
            &fixture,
            LifecycleNodeId::NodeA,
            node_a_proxy_address.unwrap_or(witness_address),
            &node_a_ready,
            node_a_spec,
        );
        let mut node_b = spawn_node(
            &fixture,
            LifecycleNodeId::NodeB,
            node_b_proxy_address.unwrap_or(witness_address),
            &node_b_ready,
            node_b_spec,
        );
        let node_a_address = wait_ready(&node_a_ready, &mut node_a);
        let node_b_address = wait_ready(&node_b_ready, &mut node_b);
        let node_a_key = SigningKey::from_bytes(&[11; 32]).verifying_key();
        let node_b_key = SigningKey::from_bytes(&[17; 32]).verifying_key();
        let controller_key = SigningKey::from_bytes(&[37; 32]);
        Self {
            _process_lab_guard: process_lab_guard,
            fixture,
            witness: Some(witness),
            witness_address,
            node_a_proxy,
            node_b_proxy,
            node_a_proxy_address,
            node_b_proxy_address,
            node_a_address,
            node_b_address,
            node_a: Some(node_a),
            node_b: Some(node_b),
            node_a_client: LifecycleClient::new(
                node_a_address,
                LifecycleNodeId::NodeA,
                node_a_key,
                controller_key.clone(),
                TIMEOUT,
            ),
            node_b_client: LifecycleClient::new(
                node_b_address,
                LifecycleNodeId::NodeB,
                node_b_key,
                controller_key,
                TIMEOUT,
            ),
        }
    }

    fn set_proxy_mode(&self, node: LifecycleNodeId, mode: &str) {
        fs::write(proxy_mode_path(&self.fixture, node), mode).expect("set fault proxy mode");
    }

    fn kill_witness(&mut self) {
        kill_child(&mut self.witness);
    }

    fn kill_node_a(&mut self) {
        kill_child(&mut self.node_a);
    }

    fn restart_node_a(&mut self, spec: NodeSpec) {
        assert!(
            self.node_a.is_none(),
            "node A must be stopped before restart"
        );
        let ready = self.fixture.root.join("node-a.ready");
        if let Err(error) = fs::remove_file(&ready) {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "remove stale node A readiness"
            );
        }
        let witness = self.node_a_proxy_address.unwrap_or(self.witness_address);
        let mut child = spawn_node(&self.fixture, LifecycleNodeId::NodeA, witness, &ready, spec);
        let address = wait_ready(&ready, &mut child);
        self.node_a_address = address;
        self.node_a = Some(child);
        self.node_a_client = LifecycleClient::new(
            address,
            LifecycleNodeId::NodeA,
            SigningKey::from_bytes(&[11; 32]).verifying_key(),
            SigningKey::from_bytes(&[37; 32]),
            TIMEOUT,
        );
    }

    fn stop_node_a(&mut self, now_ms: u64) {
        let report = self.node_a_client.stop(now_ms).expect("stop node A");
        assert_eq!(report.reason_code, LifecycleReasonCode::Stopping);
        wait_child(&mut self.node_a, true);
    }

    fn stop_node_b(&mut self, now_ms: u64) {
        let report = self.node_b_client.stop(now_ms).expect("stop node B");
        assert_eq!(report.reason_code, LifecycleReasonCode::Stopping);
        wait_child(&mut self.node_b, true);
    }

    fn pause_node_a(&mut self) {
        let child = self.node_a.as_ref().expect("node A child");
        signal(child, "-STOP");
    }

    fn resume_node_a(&mut self) {
        let child = self.node_a.as_ref().expect("node A child");
        signal(child, "-CONT");
    }
}

#[test]
fn unauthenticated_and_cross_node_control_commands_are_refused_without_state_change() {
    let mut lab = Lab::start("control-auth", NodeSpec::normal(), NodeSpec::normal());
    let node_a_key = SigningKey::from_bytes(&[11; 32]).verifying_key();
    let mut rogue = LifecycleClient::new(
        lab.node_a_address,
        LifecycleNodeId::NodeA,
        node_a_key,
        SigningKey::from_bytes(&[41; 32]),
        TIMEOUT,
    );
    let authentication_error = rogue
        .promote(1, 1_000)
        .expect_err("unknown controller must not receive an authority response");
    assert!(matches!(
        authentication_error.reason_code(),
        "LIFECYCLE_RESPONSE_READ_FAILED" | "LIFECYCLE_RESPONSE_MISSING"
    ));

    let mut wrong_target = LifecycleClient::new(
        lab.node_a_address,
        LifecycleNodeId::NodeB,
        node_a_key,
        SigningKey::from_bytes(&[37; 32]),
        TIMEOUT,
    );
    let binding_error = wrong_target
        .promote(1, 1_000)
        .expect_err("command signed for node B must not execute at node A");
    assert!(matches!(
        binding_error.reason_code(),
        "LIFECYCLE_RESPONSE_READ_FAILED" | "LIFECYCLE_RESPONSE_MISSING"
    ));

    let report = lab
        .node_a_client
        .status(1_000)
        .expect("valid authenticated status");
    assert_eq!(report.state, LifecycleState::Standby);
    assert_eq!(report.highest_epoch, 0);
    assert_eq!(report.effect_count, 0);

    let mut stale_signed = LifecycleClient::new(
        lab.node_a_address,
        LifecycleNodeId::NodeA,
        node_a_key,
        SigningKey::from_bytes(&[37; 32]),
        TIMEOUT,
    );
    let replay_error = stale_signed
        .status(999)
        .expect_err("reused controller sequence with stale time must fail");
    assert!(matches!(
        replay_error.reason_code(),
        "LIFECYCLE_RESPONSE_READ_FAILED" | "LIFECYCLE_RESPONSE_MISSING"
    ));
    let after_replay = lab
        .node_a_client
        .status(1_001)
        .expect("stale signed request must not roll back the node clock");
    assert_eq!(after_replay.state, LifecycleState::Standby);
    assert_eq!(after_replay.highest_epoch, 0);
    eprintln!(
        "security=authenticated-control status=PASS unauthorized_state_changes=0 unauthorized_effects=0 stale_signed_replays=REFUSED"
    );
}

impl Drop for Lab {
    fn drop(&mut self) {
        stop_live_node(&mut self.node_a_client, &mut self.node_a);
        stop_live_node(&mut self.node_b_client, &mut self.node_b);
        drain_proxy(&mut self.node_a_proxy, self.node_a_proxy_address);
        drain_proxy(&mut self.node_b_proxy, self.node_b_proxy_address);
        drain_witness(&mut self.witness, self.witness_address);
        let _cleanup = fs::remove_dir_all(&self.fixture.root);
    }
}

#[test]
fn normal_boot_and_first_active_selection_have_one_writer() {
    let mut lab = Lab::start("normal", NodeSpec::normal(), NodeSpec::normal());
    let a = lab.node_a_client.status(1_000).expect("status A");
    let b = lab.node_b_client.status(1_000).expect("status B");
    assert_eq!(a.state, LifecycleState::Standby);
    assert_eq!(b.state, LifecycleState::Standby);
    let promoted = lab.node_a_client.promote(1, 1_000).expect("promote A");
    assert_eq!(promoted.reason_code, LifecycleReasonCode::Promoted);
    assert_eq!(promoted.state, LifecycleState::Active);
    let effect = lab.node_a_client.emit(1, 1_001, [1; 16]).expect("emit A");
    assert_eq!(effect.reason_code, LifecycleReasonCode::EffectRecorded);
    let exact_retry = lab
        .node_a_client
        .retry_last_command()
        .expect("retry exact signed effect command");
    assert_eq!(exact_retry, effect);
    let new_request_retry = lab
        .node_a_client
        .emit(1, 1_001, [1; 16])
        .expect("retry operation under a new controller request");
    assert_eq!(
        new_request_retry.reason_code,
        LifecycleReasonCode::EffectAlreadyRecorded
    );
    assert_eq!(new_request_retry.effect_count, 1);
    let refused = lab
        .node_b_client
        .emit(1, 1_001, [2; 16])
        .expect("refuse standby effect");
    assert_eq!(refused.reason_code, LifecycleReasonCode::RefusedNotActive);
    assert_eq!(effect.effect_count + refused.effect_count, 1);
    record_pass(1, "normal_boot_first_active");
}

#[test]
fn active_sigkill_requires_expiry_and_then_promotes_standby() {
    let mut lab = Lab::start("sigkill", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_a_client
            .emit(1, 1_001, [3; 16])
            .expect("emit A")
            .reason_code
            .effect_succeeded()
    );
    lab.kill_node_a();
    let early = lab
        .node_b_client
        .promote(2, second_start - 1)
        .expect("early B promotion refusal");
    assert_eq!(
        early.reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    let promoted = lab
        .node_b_client
        .promote(2, second_start)
        .expect("promote B after guard");
    assert_eq!(promoted.reason_code, LifecycleReasonCode::Promoted);
    assert!(
        lab.node_b_client
            .emit(2, second_start + 1, [4; 16])
            .expect("emit B")
            .reason_code
            .effect_succeeded()
    );
    let recovered = recover_wal(&fs::read(&lab.fixture.node_b_wal).expect("read B WAL"))
        .expect("recover B WAL");
    assert_eq!(recovered.commit_index, 1);
    assert_eq!(recovered.value, 1);
    record_pass(2, "active_sigkill");
}

#[test]
fn automatic_controller_requires_detection_lease_guard_and_witness() {
    let mut lab = Lab::start("automatic-sigkill", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    let mut controller = LifecycleAutoController::new(2).expect("automatic policy");
    let a_boot = lab.node_a_client.status(1_000).expect("A boot status");
    let b_boot = lab.node_b_client.status(1_000).expect("B boot status");
    assert_eq!(
        controller
            .evaluate(1_000, Some(&a_boot), Some(&b_boot), true)
            .expect("bootstrap decision"),
        LifecycleAutoDecision::Promote {
            candidate: LifecycleNodeId::NodeA,
            epoch: 1,
        }
    );
    let promoted_a = lab.node_a_client.promote(1, 1_000).expect("promote A");
    controller
        .record_promotion_result(&promoted_a)
        .expect("record A promotion");
    let a_live = lab.node_a_client.status(1_001).expect("A live status");
    let b_live = lab.node_b_client.status(1_001).expect("B live status");
    assert_eq!(
        controller
            .evaluate(1_001, Some(&a_live), Some(&b_live), true)
            .expect("stable decision"),
        LifecycleAutoDecision::Stable {
            active: LifecycleNodeId::NodeA,
            epoch: 1,
        }
    );

    lab.kill_node_a();
    let b_first = lab.node_b_client.status(1_100).expect("first B probe");
    assert_eq!(
        controller
            .evaluate(1_100, None, Some(&b_first), true)
            .expect("first failure observation"),
        LifecycleAutoDecision::Hold {
            reason: LifecycleAutoReason::WaitingForFailureThreshold,
        }
    );
    let b_second = lab.node_b_client.status(1_200).expect("second B probe");
    assert_eq!(
        controller
            .evaluate(1_200, None, Some(&b_second), true)
            .expect("lease wait decision"),
        LifecycleAutoDecision::Hold {
            reason: LifecycleAutoReason::WaitingForLeaseGuard,
        }
    );
    let b_guard = lab
        .node_b_client
        .status(second_start - 1)
        .expect("guard B probe");
    assert_eq!(
        controller
            .evaluate(second_start - 1, None, Some(&b_guard), true)
            .expect("guard boundary decision"),
        LifecycleAutoDecision::Hold {
            reason: LifecycleAutoReason::WaitingForLeaseGuard,
        }
    );
    let b_ready = lab
        .node_b_client
        .status(second_start)
        .expect("ready B probe");
    assert_eq!(
        controller
            .evaluate(second_start, None, Some(&b_ready), false)
            .expect("Witness loss decision"),
        LifecycleAutoDecision::Hold {
            reason: LifecycleAutoReason::WitnessUnavailable,
        }
    );
    assert_eq!(
        controller
            .evaluate(second_start, None, Some(&b_ready), true)
            .expect("automatic failover decision"),
        LifecycleAutoDecision::Promote {
            candidate: LifecycleNodeId::NodeB,
            epoch: 2,
        }
    );
    let promoted_b = lab
        .node_b_client
        .promote(2, second_start)
        .expect("promote B");
    controller
        .record_promotion_result(&promoted_b)
        .expect("record B promotion");
    let effect = lab
        .node_b_client
        .emit(2, second_start + 1, [44; 16])
        .expect("automatic successor effect");
    assert!(effect.reason_code.effect_succeeded());
    eprintln!(
        "scenario=2 name=automatic_active_sigkill seed=1 class=github-process-autofailover status=PASS single_writer_violations=0 acknowledged_write_loss=0"
    );
}

#[test]
fn autonomous_controller_process_executes_bounded_sigkill_failover() {
    let mut lab = Lab::start(
        "controller-process-sigkill",
        NodeSpec::normal(),
        NodeSpec::normal(),
    );
    let trace_path = lab.fixture.root.join("controller.trace");
    let mut controller = spawn_auto_controller(&lab, &trace_path);
    if !wait_for_trace(
        &trace_path,
        "event=controller_effect node=node-a epoch=1",
        &mut controller,
    ) {
        let output = controller
            .wait_with_output()
            .expect("collect early controller exit");
        let node_a_log = kill_and_collect(&mut lab.node_a);
        let node_b_log = kill_and_collect(&mut lab.node_b);
        let witness_log = kill_and_collect(&mut lab.witness);
        panic!(
            "controller exited before initial effect: {}\nnode-a:\n{node_a_log}\nnode-b:\n{node_b_log}\nwitness:\n{witness_log}\ntrace:\n{}",
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(&trace_path).unwrap_or_else(|error| error.to_string())
        );
    }
    let failover_started = Instant::now();
    lab.kill_node_a();
    let output = controller.wait_with_output().expect("collect controller");
    let failure_to_effect_ms = failover_started.elapsed().as_millis();
    if !output.status.success() {
        let node_b_log = kill_and_collect(&mut lab.node_b);
        let witness_log = kill_and_collect(&mut lab.witness);
        panic!(
            "controller failed: {}\nnode-b:\n{node_b_log}\nwitness:\n{witness_log}\ntrace:\n{}",
            String::from_utf8_lossy(&output.stderr),
            fs::read_to_string(&trace_path).unwrap_or_else(|error| error.to_string())
        );
    }
    let trace = fs::read_to_string(&trace_path).expect("read controller trace");
    assert!(trace.contains(
        "event=controller_promotion node=node-a epoch=1 now_ms=1000 code=LIFECYCLE_PROMOTED promotions=1 "
    ));
    assert!(trace.contains("event=controller_promotion node=node-b epoch=2 "));
    assert!(trace.contains(
        "event=controller_effect node=node-b epoch=2 code=LIFECYCLE_EFFECT_RECORDED effects=1 "
    ));
    assert!(trace.contains("event=controller_complete node=node-b epoch=2"));
    assert_eq!(trace.matches("event=controller_promotion node=").count(), 2);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(
        "code=LIFECYCLE_CONTROLLER_COMPLETE promotions=2 final_active=node-b final_epoch=2 effects=1"
    ));
    let promotion_ms = trace_metric(
        &trace,
        "event=controller_promotion node=node-b epoch=2",
        "promotion_ms",
    );
    let successor_now_ms = trace_metric(
        &trace,
        "event=controller_promotion node=node-b epoch=2",
        "now_ms",
    );
    let (successor_start, successor_end) = lease_window(2);
    assert!(
        (u128::from(successor_start)..u128::from(successor_end)).contains(&successor_now_ms),
        "successor promotion must stay inside the epoch-2 lease window: {successor_now_ms}"
    );
    let effect_ms = trace_metric(
        &trace,
        "event=controller_effect node=node-b epoch=2",
        "effect_ms",
    );
    kill_child(&mut lab.node_b);
    eprintln!(
        "scenario=2 name=autonomous_controller_process_sigkill seed=1 class=github-process-auto-executor status=PASS single_writer_violations=0 acknowledged_write_loss=0 metric=bounded_logical_failover failure_to_effect_ms={failure_to_effect_ms} promotion_ms={promotion_ms} effect_ms={effect_ms} logical_successor_epoch=2"
    );
}

#[test]
fn automatic_controller_halts_on_untrusted_node_observation() {
    let lab = Lab::start(
        "controller-untrusted-observation",
        NodeSpec::normal(),
        NodeSpec::normal(),
    );
    let (mut proxy, proxy_address) =
        start_proxy_if_requested(&lab.fixture, "controller-node-a", lab.node_a_address, true);
    let proxy_address = proxy_address.expect("controller proxy address");
    fs::write(
        lab.fixture.root.join("controller-node-a-proxy.mode"),
        "corrupt-reply",
    )
    .expect("enable response corruption");
    let trace_path = lab.fixture.root.join("controller-untrusted.trace");
    let controller = spawn_auto_controller_at(&lab, &trace_path, proxy_address, lab.node_b_address);
    let output = controller.wait_with_output().expect("collect controller");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("LIFECYCLE_CONTROLLER_OBSERVATION_REFUSED"));
    let trace = fs::read_to_string(&trace_path).expect("read refusal trace");
    assert!(trace.contains(
        "event=controller_observation node=node-a now_ms=1000 status=REFUSED code=LIFECYCLE_RESPONSE_AUTH_REFUSED"
    ));
    assert!(!trace.contains("event=controller_promotion node="));
    assert!(!trace.contains("event=controller_effect node="));
    drain_proxy(&mut proxy, Some(proxy_address));
    eprintln!(
        "security=automatic-observation-auth status=PASS untrusted_observations=REFUSED promotions=0 effects=0"
    );
}

#[test]
fn graceful_active_shutdown_still_waits_for_safe_expiry() {
    let mut lab = Lab::start("graceful", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.stop_node_a(1_100);
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start - 1)
            .expect("refuse before expiry")
            .reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("promote after expiry")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    record_pass(3, "graceful_active_shutdown");
}

#[test]
fn standby_shutdown_does_not_change_active_authority() {
    let mut lab = Lab::start("standby-stop", NodeSpec::normal(), NodeSpec::normal());
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.stop_node_b(1_050);
    assert!(
        lab.node_a_client
            .emit(1, 1_100, [5; 16])
            .expect("active remains effective")
            .reason_code
            .effect_succeeded()
    );
    record_pass(4, "standby_shutdown");
}

#[test]
fn witness_loss_blocks_new_promotion() {
    let mut lab = Lab::start("witness-loss", NodeSpec::normal(), NodeSpec::normal());
    lab.kill_witness();
    let report = lab
        .node_a_client
        .promote(1, 1_000)
        .expect("transport returns signed refusal");
    assert_eq!(
        report.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(report.state, LifecycleState::Standby);
    assert_eq!(report.effect_count, 0);
    record_pass(5, "witness_shutdown");
}

#[test]
fn only_node_a_to_witness_connectivity_selects_at_most_node_a() {
    let mut lab = Lab::start_with_proxies(
        "partition-a-witness",
        NodeSpec::normal(),
        NodeSpec::normal(),
    );
    lab.set_proxy_mode(LifecycleNodeId::NodeB, "drop");
    let b = lab.node_b_client.promote(1, 1_000).expect("B refusal");
    assert_eq!(
        b.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(b.effect_count, 0);
    let a = lab.node_a_client.promote(1, 1_000).expect("A promotion");
    assert_eq!(a.reason_code, LifecycleReasonCode::Promoted);
    assert!(
        lab.node_a_client
            .emit(1, 1_001, [51; 16])
            .expect("A effect")
            .reason_code
            .effect_succeeded()
    );
    assert!(
        !lab.node_b_client
            .emit(1, 1_001, [52; 16])
            .expect("B remains closed")
            .reason_code
            .effect_succeeded()
    );
    record_pass(7, "node_a_witness_only");
}

#[test]
fn only_node_b_to_witness_connectivity_selects_at_most_node_b() {
    let mut lab = Lab::start_with_proxies(
        "partition-b-witness",
        NodeSpec::normal(),
        NodeSpec::normal(),
    );
    lab.set_proxy_mode(LifecycleNodeId::NodeA, "drop");
    let a = lab.node_a_client.promote(1, 1_000).expect("A refusal");
    assert_eq!(
        a.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(a.effect_count, 0);
    let b = lab.node_b_client.promote(1, 1_000).expect("B promotion");
    assert_eq!(b.reason_code, LifecycleReasonCode::Promoted);
    assert!(
        lab.node_b_client
            .emit(1, 1_001, [53; 16])
            .expect("B effect")
            .reason_code
            .effect_succeeded()
    );
    record_pass(8, "node_b_witness_only");
}

#[test]
fn complete_witness_partition_refuses_both_candidates() {
    let mut lab =
        Lab::start_with_proxies("partition-complete", NodeSpec::normal(), NodeSpec::normal());
    lab.set_proxy_mode(LifecycleNodeId::NodeA, "drop");
    lab.set_proxy_mode(LifecycleNodeId::NodeB, "drop");
    let a = lab.node_a_client.promote(1, 1_000).expect("A refusal");
    let b = lab.node_b_client.promote(1, 1_000).expect("B refusal");
    assert_eq!(
        a.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(
        b.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(a.effect_count + b.effect_count, 0);
    record_pass(9, "complete_witness_partition");
}

#[test]
fn delayed_duplicate_lost_reply_and_corrupt_frames_fail_safely() {
    {
        let mut lab =
            Lab::start_with_proxies("proxy-delay", NodeSpec::normal(), NodeSpec::normal());
        lab.set_proxy_mode(LifecycleNodeId::NodeA, "delay-ms=25");
        assert_eq!(
            lab.node_a_client
                .promote(1, 1_000)
                .expect("delayed promotion")
                .reason_code,
            LifecycleReasonCode::Promoted
        );
    }
    {
        let mut lab =
            Lab::start_with_proxies("proxy-duplicate", NodeSpec::normal(), NodeSpec::normal());
        lab.set_proxy_mode(LifecycleNodeId::NodeA, "duplicate");
        assert_eq!(
            lab.node_a_client
                .promote(1, 1_000)
                .expect("duplicate delivery")
                .reason_code,
            LifecycleReasonCode::Promoted
        );
    }
    {
        let mut lab =
            Lab::start_with_proxies("proxy-reply-drop", NodeSpec::normal(), NodeSpec::normal());
        lab.set_proxy_mode(LifecycleNodeId::NodeA, "reply-drop");
        assert_eq!(
            lab.node_a_client
                .promote(1, 1_000)
                .expect("lost reply refusal")
                .reason_code,
            LifecycleReasonCode::RefusedWitnessUnavailable
        );
        lab.set_proxy_mode(LifecycleNodeId::NodeA, "pass");
        assert_eq!(
            lab.node_a_client
                .promote(1, 1_000)
                .expect("exact durable retry")
                .reason_code,
            LifecycleReasonCode::Promoted
        );
    }
    {
        let mut lab =
            Lab::start_with_proxies("proxy-corrupt", NodeSpec::normal(), NodeSpec::normal());
        lab.set_proxy_mode(LifecycleNodeId::NodeA, "corrupt");
        let refusal = lab
            .node_a_client
            .promote(1, 1_000)
            .expect("corrupt frame refusal");
        assert_eq!(
            refusal.reason_code,
            LifecycleReasonCode::RefusedWitnessUnavailable
        );
        assert_eq!(refusal.effect_count, 0);
    }
    record_pass(10, "delay_duplicate_reply_drop_corrupt");
}

#[test]
fn stale_witness_exchange_replay_self_fences_requesting_node() {
    let mut lab = Lab::start_with_proxies("proxy-replay", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    let (third_start, _) = lease_window(3);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("B epoch 2")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.set_proxy_mode(LifecycleNodeId::NodeA, "replay-last");
    let replay = lab
        .node_a_client
        .promote(3, third_start)
        .expect("signed stale Witness response refusal");
    assert_eq!(
        replay.reason_code,
        LifecycleReasonCode::RefusedWitnessUnavailable
    );
    assert_eq!(replay.state, LifecycleState::SelfFenced);
    assert_eq!(replay.effect_count, 0);
    record_pass(13, "stale_witness_exchange_replay");
}

#[test]
fn restarted_older_node_cannot_resurrect_previous_epoch() {
    let mut lab = Lab::start("restart-old-epoch", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.kill_node_a();
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("B epoch 2")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.restart_node_a(NodeSpec::normal());
    let stale = lab
        .node_a_client
        .promote(1, 1_100)
        .expect("old epoch restart refusal");
    assert_eq!(stale.reason_code, LifecycleReasonCode::RefusedDurability);
    assert_eq!(stale.state, LifecycleState::SelfFenced);
    assert!(stale.incarnation >= 2);
    assert_eq!(stale.effect_count, 0);
    assert!(
        lab.node_b_client
            .emit(2, second_start + 1, [54; 16])
            .expect("new authority remains effective")
            .reason_code
            .effect_succeeded()
    );
    record_pass(19, "restart_with_older_epoch");
}

#[test]
fn witness_double_vote_refusal_prevents_second_activation() {
    let mut lab = Lab::start("double-vote", NodeSpec::normal(), NodeSpec::normal());
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let refused = lab
        .node_b_client
        .promote(1, 1_000)
        .expect("same-epoch B refusal");
    assert_eq!(refused.reason_code, LifecycleReasonCode::RefusedWitnessVote);
    assert_eq!(refused.state, LifecycleState::Standby);
    assert_eq!(refused.effect_count, 0);
    let a = lab
        .node_a_client
        .emit(1, 1_001, [55; 16])
        .expect("A effect");
    let b = lab
        .node_b_client
        .emit(1, 1_001, [56; 16])
        .expect("B effect refusal");
    assert!(a.reason_code.effect_succeeded());
    assert!(!b.reason_code.effect_succeeded());
    record_pass(23, "witness_double_vote_attempt");
}

#[test]
fn duplicate_acknowledged_workload_operation_is_confirmed_after_failover() {
    let mut lab = Lab::start(
        "workload-retry-failover",
        NodeSpec::normal(),
        NodeSpec::normal(),
    );
    let original_a = fs::read(&lab.fixture.node_a_wal).expect("read original A WAL");
    let original_b = fs::read(&lab.fixture.node_b_wal).expect("read original B WAL");
    let (second_start, _) = lease_window(2);
    assert_eq!(original_a, original_b);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    lab.kill_node_a();
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("B epoch 2")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let confirmed = lab
        .node_b_client
        .retry_workload(2, second_start + 1, [9; 16])
        .expect("confirm recovered operation");
    assert_eq!(
        confirmed.reason_code,
        LifecycleReasonCode::WorkloadRetryConfirmed
    );
    assert_eq!(confirmed.state, LifecycleState::Active);
    assert_eq!(confirmed.commit_index, 1);
    assert_eq!(
        lab.node_b_client
            .retry_last_command()
            .expect("exact controller retry"),
        confirmed
    );
    let repeated = lab
        .node_b_client
        .retry_workload(2, second_start + 2, [9; 16])
        .expect("new signed request for same operation");
    assert_eq!(
        repeated.reason_code,
        LifecycleReasonCode::WorkloadRetryConfirmed
    );
    let unknown = lab
        .node_b_client
        .retry_workload(2, second_start + 3, [57; 16])
        .expect("unknown operation refusal");
    assert_eq!(
        unknown.reason_code,
        LifecycleReasonCode::RefusedWorkloadRetry
    );
    assert_eq!(unknown.state, LifecycleState::Active);
    assert_eq!(
        fs::read(&lab.fixture.node_a_wal).expect("read final A WAL"),
        original_a
    );
    assert_eq!(
        fs::read(&lab.fixture.node_b_wal).expect("read final B WAL"),
        original_b
    );
    let recovered = recover_wal(&original_b).expect("recover single durable record");
    assert_eq!(recovered.commit_index, 1);
    assert_eq!(recovered.value, 1);
    record_pass(20, "duplicate_workload_operation_after_failover");
}

#[test]
fn lagging_candidate_is_refused_before_witness_authority() {
    let lagging = NodeSpec {
        wal: WalMode::Empty,
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("lagging", NodeSpec::normal(), lagging);
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let report = lab
        .node_b_client
        .promote(2, second_start)
        .expect("lag refusal");
    assert_eq!(
        report.reason_code,
        LifecycleReasonCode::RefusedCandidateLagging
    );
    assert_eq!(report.effect_count, 0);
    record_pass(11, "candidate_data_lag");
}

#[test]
fn early_promotion_does_not_burn_witness_epoch() {
    let mut lab = Lab::start("early", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start - 1)
            .expect("early refusal")
            .reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("later exact promotion")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    record_pass(15, "early_promotion");
}

#[test]
fn late_promotion_window_uses_fresh_witness_fence_evidence() {
    let mut lab = Lab::start("late-window", NodeSpec::normal(), NodeSpec::normal());
    let (_, second_end) = lease_window(2);
    let late_promotion_ms = second_end - 50;
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let promoted = lab
        .node_b_client
        .promote(2, late_promotion_ms)
        .expect("late in-window B promotion");
    assert_eq!(promoted.reason_code, LifecycleReasonCode::Promoted);
    assert!(
        lab.node_b_client
            .emit(2, late_promotion_ms + 1, [62; 16])
            .expect("late-window B effect")
            .reason_code
            .effect_succeeded()
    );
    eprintln!(
        "security=fresh-witness-fence-window status=PASS promotion_now_ms={late_promotion_ms} window_end_ms={second_end} single_writer_violations=0"
    );
}

#[test]
fn simultaneous_same_epoch_candidates_have_at_most_one_effective_writer() {
    let mut lab = Lab::start("same-epoch", NodeSpec::normal(), NodeSpec::normal());
    let (a_report, b_report) = thread::scope(|scope| {
        let a_client = &mut lab.node_a_client;
        let b_client = &mut lab.node_b_client;
        let a = scope.spawn(|| a_client.promote(1, 1_000).expect("A promotion response"));
        let b = scope.spawn(|| b_client.promote(1, 1_000).expect("B promotion response"));
        (
            a.join().expect("join A promotion"),
            b.join().expect("join B promotion"),
        )
    });
    let promotions = [a_report.reason_code, b_report.reason_code]
        .into_iter()
        .filter(|code| *code == LifecycleReasonCode::Promoted)
        .count();
    assert_eq!(promotions, 1);
    assert_eq!(a_report.effect_count + b_report.effect_count, 0);
    let a_effect = lab
        .node_a_client
        .emit(1, 1_001, [31; 16])
        .expect("A effect decision");
    let b_effect = lab
        .node_b_client
        .emit(1, 1_001, [32; 16])
        .expect("B effect decision");
    let effective_writers = [a_effect.reason_code, b_effect.reason_code]
        .into_iter()
        .filter(|code| code.effect_succeeded())
        .count();
    assert_eq!(effective_writers, 1);
    record_pass(14, "simultaneous_same_epoch_candidates");
}

#[test]
fn stale_signed_promotion_replay_is_refused_without_closing_live_authority() {
    let mut lab = Lab::start("replay", NodeSpec::normal(), NodeSpec::normal());
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let replay = lab
        .node_a_client
        .replay_last_proof(1_001)
        .expect("replay response");
    assert_eq!(replay.reason_code, LifecycleReasonCode::RefusedReplay);
    assert_eq!(replay.state, LifecycleState::Active);
    assert!(
        lab.node_a_client
            .emit(1, 1_002, [6; 16])
            .expect("original authority remains live")
            .reason_code
            .effect_succeeded()
    );
    record_pass(12, "old_promotion_proof_replay");
}

#[test]
fn policy_mismatch_is_fail_closed() {
    let wrong_policy = NodeSpec {
        policy_byte: lifecycle_policy_hash()[0].wrapping_add(1),
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("policy", wrong_policy, NodeSpec::normal());
    let report = lab.node_a_client.promote(1, 1_000).expect("policy refusal");
    assert_eq!(report.reason_code, LifecycleReasonCode::RefusedPolicy);
    assert_eq!(report.effect_count, 0);
    record_pass(22, "policy_hash_mismatch");
}

#[test]
fn state_root_mismatch_is_fail_closed() {
    let different = NodeSpec {
        wal: WalMode::DifferentRoot,
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("root", different, NodeSpec::normal());
    let report = lab.node_a_client.promote(1, 1_000).expect("root refusal");
    assert_eq!(
        report.reason_code,
        LifecycleReasonCode::RefusedCandidateLagging
    );
    assert_eq!(report.effect_count, 0);
    record_pass(21, "state_root_mismatch");
}

#[test]
fn promotion_store_write_failure_poison_fences_before_effect() {
    let faulted = NodeSpec {
        store_fault: "promotion-write",
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("store-write", faulted, NodeSpec::normal());
    let report = lab
        .node_a_client
        .promote(1, 1_000)
        .expect("durability refusal");
    assert_eq!(report.reason_code, LifecycleReasonCode::RefusedDurability);
    assert_eq!(report.state, LifecycleState::SelfFenced);
    assert_eq!(report.effect_count, 0);
    let later = lab
        .node_a_client
        .emit(1, 1_001, [7; 16])
        .expect("closed gate response");
    assert!(!later.reason_code.effect_succeeded());
    record_pass(17, "durable_store_failure");
}

#[test]
fn promotion_partial_write_poison_fences_before_effect() {
    let faulted = NodeSpec {
        store_fault: "promotion-partial",
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("store-partial", faulted, NodeSpec::normal());
    let report = lab
        .node_a_client
        .promote(1, 1_000)
        .expect("partial durability refusal");
    assert_eq!(report.reason_code, LifecycleReasonCode::RefusedDurability);
    assert_eq!(report.state, LifecycleState::SelfFenced);
    assert_eq!(report.effect_count, 0);
    record_pass(18, "partial_store_write");
}

#[test]
fn clock_rollback_self_fences_active_node() {
    let mut lab = Lab::start("clock", NodeSpec::normal(), NodeSpec::normal());
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_a_client
            .emit(1, 1_100, [8; 16])
            .expect("effect before rollback")
            .reason_code
            .effect_succeeded()
    );
    let rollback = lab
        .node_a_client
        .status(1_050)
        .expect("signed rollback refusal");
    assert_eq!(
        rollback.reason_code,
        LifecycleReasonCode::RefusedClockRollback
    );
    assert_eq!(rollback.state, LifecycleState::SelfFenced);
    assert!(
        !lab.node_a_client
            .emit(1, 1_051, [9; 16])
            .expect("effect remains refused")
            .reason_code
            .effect_succeeded()
    );
    record_pass(16, "clock_rollback");
}

#[test]
fn paused_old_active_self_fences_before_effect_after_resume() {
    let mut lab = Lab::start("pause", NodeSpec::normal(), NodeSpec::normal());
    let (second_start, _) = lease_window(2);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_a_client
            .emit(1, 1_001, [10; 16])
            .expect("A effect")
            .reason_code
            .effect_succeeded()
    );
    lab.pause_node_a();
    assert_eq!(
        lab.node_b_client
            .promote(2, second_start)
            .expect("promote B after A lease")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_b_client
            .emit(2, second_start + 1, [11; 16])
            .expect("B effect")
            .reason_code
            .effect_succeeded()
    );
    lab.resume_node_a();
    let old = lab
        .node_a_client
        .emit(1, second_start + 1, [12; 16])
        .expect("resumed A refusal");
    assert!(!old.reason_code.effect_succeeded());
    assert_eq!(old.state, LifecycleState::SelfFenced);
    record_pass(24, "process_pause_resume");
}

#[test]
fn repeated_failover_and_failback_keep_epochs_monotonic() {
    let mut lab = Lab::start("cycles", NodeSpec::normal(), NodeSpec::normal());
    let (t1, _) = lifecycle_lease(1).expect("epoch 1 lease");
    let (t2, _) = lifecycle_lease(2).expect("epoch 2 lease");
    let (t3, _) = lifecycle_lease(3).expect("epoch 3 lease");
    let (t4, _) = lifecycle_lease(4).expect("epoch 4 lease");
    assert_eq!(
        lab.node_a_client
            .promote(1, t1)
            .expect("A epoch 1")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_a_client
            .emit(1, t1 + 1, [13; 16])
            .expect("A effect 1")
            .reason_code
            .effect_succeeded()
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, t2)
            .expect("B epoch 2")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_b_client
            .emit(2, t2 + 1, [14; 16])
            .expect("B effect 2")
            .reason_code
            .effect_succeeded()
    );
    assert_eq!(
        lab.node_a_client
            .promote(3, t3)
            .expect("A epoch 3")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_a_client
            .emit(3, t3 + 1, [15; 16])
            .expect("A effect 3")
            .reason_code
            .effect_succeeded()
    );
    assert_eq!(
        lab.node_b_client
            .promote(4, t4)
            .expect("B epoch 4")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let final_effect = lab
        .node_b_client
        .emit(4, t4 + 1, [16; 16])
        .expect("B effect 4");
    assert!(final_effect.reason_code.effect_succeeded());
    assert_eq!(final_effect.highest_epoch, 4);
    record_pass(25, "repeated_failover_failback");
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_quorumarc-cluster"))
}

fn lease_window(epoch: u64) -> (u64, u64) {
    lifecycle_lease(epoch).expect("valid lifecycle lease")
}

fn start_proxy_if_requested(
    fixture: &Fixture,
    label: &str,
    witness: SocketAddr,
    requested: bool,
) -> (Option<Child>, Option<SocketAddr>) {
    if !requested {
        return (None, None);
    }
    let ready = fixture.root.join(format!("{label}-proxy.ready"));
    let mode = fixture.root.join(format!("{label}-proxy.mode"));
    fs::write(&mode, "pass").expect("create fault proxy mode");
    let mut child = Command::new(binary())
        .arg("fault-proxy")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(&ready)
        .arg("--upstream")
        .arg(witness.to_string())
        .arg("--mode-file")
        .arg(&mode)
        .arg("--max-connections")
        .arg(PROXY_MAX_CONNECTIONS.to_string())
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--allow-lifecycle-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fault proxy");
    let address = wait_ready(&ready, &mut child);
    (Some(child), Some(address))
}

fn proxy_mode_path(fixture: &Fixture, node: LifecycleNodeId) -> PathBuf {
    let label = match node {
        LifecycleNodeId::NodeA => "node-a",
        LifecycleNodeId::NodeB => "node-b",
    };
    fixture.root.join(format!("{label}-proxy.mode"))
}

fn spawn_witness(fixture: &Fixture, ready: &Path) -> Child {
    Command::new(binary())
        .arg("lifecycle-witness")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--store")
        .arg(fixture.root.join("witness-store"))
        .arg("--signing-key")
        .arg(&fixture.witness_seed)
        .arg("--node-a-public-key")
        .arg(&fixture.node_a_public)
        .arg("--node-b-public-key")
        .arg(&fixture.node_b_public)
        .arg("--max-connections")
        .arg(WITNESS_MAX_CONNECTIONS.to_string())
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--allow-lifecycle-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lifecycle witness")
}

fn spawn_node(
    fixture: &Fixture,
    node: LifecycleNodeId,
    witness: SocketAddr,
    ready: &Path,
    spec: NodeSpec,
) -> Child {
    let (seed, wal, store) = match node {
        LifecycleNodeId::NodeA => (
            &fixture.node_a_seed,
            &fixture.node_a_wal,
            fixture.root.join("node-a-store"),
        ),
        LifecycleNodeId::NodeB => (
            &fixture.node_b_seed,
            &fixture.node_b_wal,
            fixture.root.join("node-b-store"),
        ),
    };
    Command::new(binary())
        .arg("lifecycle-node")
        .arg("--node")
        .arg(node.as_str())
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--wal")
        .arg(wal)
        .arg("--store")
        .arg(store)
        .arg("--signing-key")
        .arg(seed)
        .arg("--witness-public-key")
        .arg(&fixture.witness_public)
        .arg("--controller-public-key")
        .arg(&fixture.controller_public)
        .arg("--witness")
        .arg(witness.to_string())
        .arg("--max-connections")
        .arg("64")
        .arg("--timeout-ms")
        .arg("10000")
        .arg("--policy-byte")
        .arg(spec.policy_byte.to_string())
        .arg("--store-fault")
        .arg(spec.store_fault)
        .arg("--allow-lifecycle-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lifecycle node")
}

fn spawn_auto_controller(lab: &Lab, trace: &Path) -> Child {
    spawn_auto_controller_at(lab, trace, lab.node_a_address, lab.node_b_address)
}

fn spawn_auto_controller_at(
    lab: &Lab,
    trace: &Path,
    node_a_address: SocketAddr,
    node_b_address: SocketAddr,
) -> Child {
    Command::new(binary())
        .arg("lifecycle-controller")
        .arg("--node-a")
        .arg(node_a_address.to_string())
        .arg("--node-b")
        .arg(node_b_address.to_string())
        .arg("--node-a-public-key")
        .arg(&lab.fixture.node_a_public)
        .arg("--node-b-public-key")
        .arg(&lab.fixture.node_b_public)
        .arg("--controller-signing-key")
        .arg(&lab.fixture.controller_seed)
        .arg("--trace-file")
        .arg(trace)
        .arg("--failure-threshold")
        .arg("2")
        .arg("--max-promotions")
        .arg("2")
        .arg("--logical-step-ms")
        .arg("10")
        .arg("--poll-ms")
        .arg("20")
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--max-runtime-ms")
        .arg("10000")
        .arg("--emit-test-effect")
        .arg("--allow-lifecycle-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn automatic lifecycle controller")
}

fn trace_metric(trace: &str, event_prefix: &str, metric: &str) -> u128 {
    let line = trace
        .lines()
        .find(|line| line.starts_with(event_prefix))
        .unwrap_or_else(|| panic!("missing trace event: {event_prefix}"));
    let prefix = format!("{metric}=");
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing trace metric {metric}: {line}"))
        .parse::<u128>()
        .unwrap_or_else(|error| panic!("invalid trace metric {metric}: {error}"))
}

fn wait_ready(path: &Path, child: &mut Child) -> SocketAddr {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            if let Ok(address) = SocketAddr::from_str(value.trim()) {
                return address;
            }
        }
        assert!(
            child.try_wait().expect("inspect child").is_none(),
            "service exited before readiness"
        );
        assert!(Instant::now() < deadline, "service readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_trace(path: &Path, expected: &str, child: &mut Child) -> bool {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if fs::read_to_string(path).is_ok_and(|trace| trace.contains(expected)) {
            return true;
        }
        if child.try_wait().expect("inspect controller").is_some() || Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn seed_acknowledged_write(node_a: &Path, node_b: &Path) {
    let mut counter = ReplicatedCounter::new();
    let mut first = FileReplica::new("node-a", node_a);
    let mut second = FileReplica::new("node-b", node_b);
    let acknowledged = counter
        .apply(
            CounterOperation {
                id: OperationId::new([9; 16]),
                expected_commit_index: 0,
                increment: 1,
            },
            &mut first,
            &mut second,
        )
        .expect("seed acknowledged RPO-0 write");
    assert_eq!(acknowledged.commit_index, 1);
    assert_eq!(acknowledged.value, 1);
}

fn apply_wal_mode(path: &Path, mode: WalMode) {
    match mode {
        WalMode::Expected => {}
        WalMode::Empty => {
            fs::write(path, []).expect("empty lagging WAL");
        }
        WalMode::DifferentRoot => {
            let entry = WalEntry {
                commit_index: 1,
                operation_id: OperationId::new([19; 16]),
                previous_value: 0,
                increment: 2,
                value: 2,
            };
            let mut file = File::create(path).expect("replace mismatched WAL");
            file.write_all(&entry.encode())
                .expect("write mismatched WAL");
            file.sync_all().expect("sync mismatched WAL");
        }
    }
}

fn write_public(path: &Path, seed: [u8; 32]) {
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let mut file = File::create(path).expect("create public key");
    file.write_all(key.as_bytes()).expect("write public key");
    file.sync_all().expect("sync public key");
}

fn write_private(path: &Path, seed: [u8; 32]) {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .expect("create private key");
    file.write_all(&seed).expect("write private key");
    file.sync_all().expect("sync private key");
}

fn signal(child: &Child, signal: &str) {
    let status = Command::new("kill")
        .arg(signal)
        .arg(child.id().to_string())
        .status()
        .expect("send signal");
    assert!(status.success(), "signal {signal} failed");
}

fn kill_child(child: &mut Option<Child>) {
    let Some(mut child) = child.take() else {
        return;
    };
    let _kill = child.kill();
    let _wait = child.wait();
}

fn kill_and_collect(child: &mut Option<Child>) -> String {
    let Some(mut child) = child.take() else {
        return String::new();
    };
    let _kill = child.kill();
    match child.wait_with_output() {
        Ok(output) => format!(
            "stdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(error) => format!("collect failed: {error}"),
    }
}

fn stop_live_node(client: &mut LifecycleClient, child: &mut Option<Child>) {
    let Some(process) = child.as_mut() else {
        return;
    };
    if process
        .try_wait()
        .expect("inspect node during cleanup")
        .is_some()
    {
        let _finished = child.take();
        return;
    }
    let _response = client.stop(10_000);
    let Some(mut process) = child.take() else {
        return;
    };
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if process.try_wait().expect("inspect stopping node").is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let _kill = process.kill();
            let _wait = process.wait();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn drain_witness(child: &mut Option<Child>, address: SocketAddr) {
    let Some(process) = child.as_mut() else {
        return;
    };
    if process
        .try_wait()
        .expect("inspect witness during cleanup")
        .is_some()
    {
        let _finished = child.take();
        return;
    }

    // The bounded lab Witness exits normally after its configured connection
    // budget. Supplying canonical zero-length frame headers exercises refusal
    // handling and lets coverage/runtime instrumentation flush without adding
    // an unauthenticated shutdown command to the service protocol.
    for _ in 0..=WITNESS_MAX_CONNECTIONS {
        if process
            .try_wait()
            .expect("inspect draining witness")
            .is_some()
        {
            break;
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, TIMEOUT) {
            let _timeout = stream.set_write_timeout(Some(TIMEOUT));
            let _write = stream.write_all(&0_u32.to_be_bytes());
        }
    }

    let Some(mut process) = child.take() else {
        return;
    };
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if process
            .try_wait()
            .expect("inspect drained witness")
            .is_some()
        {
            return;
        }
        if Instant::now() >= deadline {
            let _kill = process.kill();
            let _wait = process.wait();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn drain_proxy(child: &mut Option<Child>, address: Option<SocketAddr>) {
    let (Some(process), Some(address)) = (child.as_mut(), address) else {
        return;
    };
    if process
        .try_wait()
        .expect("inspect proxy during cleanup")
        .is_some()
    {
        let _finished = child.take();
        return;
    }

    for _ in 0..=PROXY_MAX_CONNECTIONS {
        if process
            .try_wait()
            .expect("inspect draining proxy")
            .is_some()
        {
            break;
        }
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, TIMEOUT) {
            let _timeout = stream.set_write_timeout(Some(TIMEOUT));
            let _write = stream.write_all(&0_u32.to_be_bytes());
        }
    }

    let Some(mut process) = child.take() else {
        return;
    };
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if process.try_wait().expect("inspect drained proxy").is_some() {
            return;
        }
        if Instant::now() >= deadline {
            let _kill = process.kill();
            let _wait = process.wait();
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_child(child: &mut Option<Child>, expected_success: bool) {
    let Some(mut child) = child.take() else {
        panic!("child is missing");
    };
    let status = child.wait().expect("wait child");
    assert_eq!(status.success(), expected_success);
}

fn record_pass(scenario: u8, name: &str) {
    eprintln!(
        "scenario={scenario} name={name} seed=1 class=github-process-lifecycle status=PASS single_writer_violations=0 acknowledged_write_loss=0"
    );
}
