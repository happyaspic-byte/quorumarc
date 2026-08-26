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
use std::thread;
use std::time::{Duration, Instant};

use quorumarc_cluster::{
    LifecycleClient, LifecycleNodeId, LifecycleReasonCode, LifecycleState, lifecycle_lease,
    lifecycle_policy_hash,
};
use quorumarc_rpo0::{
    CounterOperation, FileReplica, OperationId, ReplicatedCounter, WalEntry, recover_wal,
};
use quorumarc_wire::SigningKey;

static NEXT: AtomicU64 = AtomicU64::new(1);
const TIMEOUT: Duration = Duration::from_secs(3);
const WITNESS_MAX_CONNECTIONS: usize = 16;

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
    node_a_public: PathBuf,
    node_b_public: PathBuf,
    witness_public: PathBuf,
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
            node_a_public: root.join("node-a.public"),
            node_b_public: root.join("node-b.public"),
            witness_public: root.join("witness.public"),
            node_a_wal: root.join("node-a.wal"),
            node_b_wal: root.join("node-b.wal"),
            root,
        };
        write_private(&fixture.node_a_seed, [11; 32]);
        write_private(&fixture.node_b_seed, [17; 32]);
        write_private(&fixture.witness_seed, [29; 32]);
        write_public(&fixture.node_a_public, [11; 32]);
        write_public(&fixture.node_b_public, [17; 32]);
        write_public(&fixture.witness_public, [29; 32]);
        seed_acknowledged_write(&fixture.node_a_wal, &fixture.node_b_wal);
        apply_wal_mode(&fixture.node_a_wal, node_a.wal);
        apply_wal_mode(&fixture.node_b_wal, node_b.wal);
        fixture
    }
}

struct Lab {
    fixture: Fixture,
    witness: Option<Child>,
    witness_address: SocketAddr,
    node_a: Option<Child>,
    node_b: Option<Child>,
    node_a_client: LifecycleClient,
    node_b_client: LifecycleClient,
}

impl Lab {
    fn start(label: &str, node_a_spec: NodeSpec, node_b_spec: NodeSpec) -> Self {
        let fixture = Fixture::new(label, node_a_spec, node_b_spec);
        let witness_ready = fixture.root.join("witness.ready");
        let mut witness = spawn_witness(&fixture, &witness_ready);
        let witness_address = wait_ready(&witness_ready, &mut witness);
        let node_a_ready = fixture.root.join("node-a.ready");
        let node_b_ready = fixture.root.join("node-b.ready");
        let mut node_a = spawn_node(
            &fixture,
            LifecycleNodeId::NodeA,
            witness_address,
            &node_a_ready,
            node_a_spec,
        );
        let mut node_b = spawn_node(
            &fixture,
            LifecycleNodeId::NodeB,
            witness_address,
            &node_b_ready,
            node_b_spec,
        );
        let node_a_address = wait_ready(&node_a_ready, &mut node_a);
        let node_b_address = wait_ready(&node_b_ready, &mut node_b);
        let node_a_key = SigningKey::from_bytes(&[11; 32]).verifying_key();
        let node_b_key = SigningKey::from_bytes(&[17; 32]).verifying_key();
        Self {
            fixture,
            witness: Some(witness),
            witness_address,
            node_a: Some(node_a),
            node_b: Some(node_b),
            node_a_client: LifecycleClient::new(
                node_a_address,
                LifecycleNodeId::NodeA,
                node_a_key,
                TIMEOUT,
            ),
            node_b_client: LifecycleClient::new(
                node_b_address,
                LifecycleNodeId::NodeB,
                node_b_key,
                TIMEOUT,
            ),
        }
    }

    fn kill_witness(&mut self) {
        kill_child(&mut self.witness);
    }

    fn kill_node_a(&mut self) {
        kill_child(&mut self.node_a);
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

impl Drop for Lab {
    fn drop(&mut self) {
        stop_live_node(&mut self.node_a_client, &mut self.node_a);
        stop_live_node(&mut self.node_b_client, &mut self.node_b);
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
        .promote(2, 1_249)
        .expect("early B promotion refusal");
    assert_eq!(
        early.reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    let promoted = lab
        .node_b_client
        .promote(2, 1_250)
        .expect("promote B after guard");
    assert_eq!(promoted.reason_code, LifecycleReasonCode::Promoted);
    assert!(
        lab.node_b_client
            .emit(2, 1_251, [4; 16])
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
fn graceful_active_shutdown_still_waits_for_safe_expiry() {
    let mut lab = Lab::start("graceful", NodeSpec::normal(), NodeSpec::normal());
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
            .promote(2, 1_200)
            .expect("refuse before expiry")
            .reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, 1_250)
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
fn lagging_candidate_is_refused_before_witness_authority() {
    let lagging = NodeSpec {
        wal: WalMode::Empty,
        ..NodeSpec::normal()
    };
    let mut lab = Lab::start("lagging", NodeSpec::normal(), lagging);
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    let report = lab.node_b_client.promote(2, 1_250).expect("lag refusal");
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
    assert_eq!(
        lab.node_a_client
            .promote(1, 1_000)
            .expect("promote A")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, 1_249)
            .expect("early refusal")
            .reason_code,
        LifecycleReasonCode::RefusedLeaseNotActive
    );
    assert_eq!(
        lab.node_b_client
            .promote(2, 1_250)
            .expect("later exact promotion")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    record_pass(15, "early_promotion");
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
            .promote(2, 1_250)
            .expect("promote B after A lease")
            .reason_code,
        LifecycleReasonCode::Promoted
    );
    assert!(
        lab.node_b_client
            .emit(2, 1_251, [11; 16])
            .expect("B effect")
            .reason_code
            .effect_succeeded()
    );
    lab.resume_node_a();
    let old = lab
        .node_a_client
        .emit(1, 1_251, [12; 16])
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
        .arg("3000")
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
        .arg("--witness")
        .arg(witness.to_string())
        .arg("--max-connections")
        .arg("64")
        .arg("--timeout-ms")
        .arg("3000")
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

fn wait_ready(path: &Path, child: &mut Child) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(5);
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
