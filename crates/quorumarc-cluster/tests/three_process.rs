#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::unwrap_used)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use quorumarc_rpo0::recover_wal;
use quorumarc_store::{DurableAuthorityStore, FileBackend, StoreIdentity, StoreRole};
use quorumarc_wire::SigningKey;

static NEXT: AtomicU64 = AtomicU64::new(1);

fn candidate_store_identity() -> StoreIdentity {
    StoreIdentity::new(
        "gate1a-lab",
        "orders",
        "node-a",
        StoreRole::DataNode,
        [61; 16],
    )
    .expect("valid candidate fixture identity")
}

fn witness_store_identity() -> StoreIdentity {
    StoreIdentity::new(
        "gate1a-lab",
        "orders",
        "witness",
        StoreRole::Witness,
        [71; 16],
    )
    .expect("valid witness fixture identity")
}

struct Fixture {
    root: PathBuf,
    candidate_seed: PathBuf,
    peer_seed: PathBuf,
    witness_seed: PathBuf,
    candidate_public: PathBuf,
    peer_public: PathBuf,
    witness_public: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "quorumarc-cluster-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create fixture directory");
        let candidate_seed = root.join("node-a.seed");
        let peer_seed = root.join("node-b.seed");
        let witness_seed = root.join("witness.seed");
        let candidate_public = root.join("node-a.public");
        let peer_public = root.join("node-b.public");
        let witness_public = root.join("witness.public");
        write_private(&candidate_seed, [11; 32]);
        write_private(&peer_seed, [17; 32]);
        write_private(&witness_seed, [29; 32]);
        write_public(&candidate_public, [11; 32]);
        write_public(&peer_public, [17; 32]);
        write_public(&witness_public, [29; 32]);
        Self {
            root,
            candidate_seed,
            peer_seed,
            witness_seed,
            candidate_public,
            peer_public,
            witness_public,
        }
    }

    fn cleanup(self) {
        fs::remove_dir_all(self.root).expect("remove fixture directory");
    }
}

#[test]
fn three_child_processes_complete_one_shot_genesis() {
    let fixture = Fixture::new("happy");
    let peer_wal = fixture.root.join("node-b.wal");
    let local_wal = fixture.root.join("node-a.wal");
    let witness_store = fixture.root.join("witness-store");
    let candidate_store = fixture.root.join("candidate-store");
    let peer_ready = fixture.root.join("peer.ready");
    let witness_ready = fixture.root.join("witness.ready");
    let mut peer = spawn_peer(&fixture, &peer_wal, &peer_ready, 1);
    let mut witness = spawn_witness(&fixture, &witness_store, &witness_ready, 1);
    let peer_address = wait_ready(&peer_ready, &mut peer);
    let witness_address = wait_ready(&witness_ready, &mut witness);
    let candidate = run_candidate(
        &fixture,
        peer_address,
        witness_address,
        &local_wal,
        &candidate_store,
    );
    if !candidate.status.success() {
        let _peer_kill = peer.kill();
        let _witness_kill = witness.kill();
    }
    let peer_output = peer.wait_with_output().expect("collect peer output");
    let witness_output = witness.wait_with_output().expect("collect witness output");
    assert_success("candidate", &candidate);
    assert_success("peer", &peer_output);
    assert_success("witness", &witness_output);
    let stdout = String::from_utf8_lossy(&candidate.stdout);
    assert!(stdout.contains("code=LAB_GENESIS_ONE_SHOT"));
    assert!(stdout.contains("commit_index=1"));
    assert!(stdout.contains("value=1"));
    assert!(stdout.contains("effects=1"));
    assert!(stdout.contains("store_generation=4"));

    let local_bytes = fs::read(&local_wal).expect("read candidate WAL");
    let peer_bytes = fs::read(&peer_wal).expect("read peer WAL");
    assert_eq!(local_bytes, peer_bytes);
    let recovered = recover_wal(&local_bytes).expect("recover identical WAL");
    assert_eq!(recovered.commit_index, 1);
    assert_eq!(recovered.value, 1);

    let candidate_state =
        DurableAuthorityStore::open_in(&candidate_store, candidate_store_identity(), FileBackend)
            .expect("recover candidate authority");
    assert_eq!(candidate_state.generation(), 4);
    assert_eq!(candidate_state.state().highest_epoch(), 1);
    assert_eq!(candidate_state.state().incarnation(), 7);
    assert!(candidate_state.state().activation_receipt().is_some());
    let witness_state =
        DurableAuthorityStore::open_in(&witness_store, witness_store_identity(), FileBackend)
            .expect("recover witness authority");
    assert_eq!(witness_state.generation(), 1);
    assert_eq!(witness_state.state().highest_epoch(), 1);

    assert!(candidate_store.join(".quorumarc.owner").is_file());
    assert!(witness_store.join(".quorumarc.owner").is_file());
    assert!(lock_for_file(&local_wal).is_file());
    assert!(lock_for_file(&peer_wal).is_file());
    fixture.cleanup();
}

#[test]
fn ab_replication_partition_refuses_acknowledgement_and_authority() {
    let fixture = Fixture::new("ab-partition");
    let peer_wal = fixture.root.join("node-b.wal");
    let local_wal = fixture.root.join("node-a.wal");
    let witness_store = fixture.root.join("witness-store");
    let candidate_store = fixture.root.join("candidate-store");
    let peer_ready = fixture.root.join("peer.ready");
    let witness_ready = fixture.root.join("witness.ready");
    let proxy_ready = fixture.root.join("peer-proxy.ready");
    let proxy_mode = fixture.root.join("peer-proxy.mode");
    fs::write(&proxy_mode, "drop").expect("create peer proxy mode");
    let mut peer = spawn_peer(&fixture, &peer_wal, &peer_ready, 1);
    let mut witness = spawn_witness(&fixture, &witness_store, &witness_ready, 1);
    let peer_address = wait_ready(&peer_ready, &mut peer);
    let witness_address = wait_ready(&witness_ready, &mut witness);
    let mut proxy = spawn_fault_proxy(peer_address, &proxy_ready, &proxy_mode, 1);
    let proxy_address = wait_ready(&proxy_ready, &mut proxy);
    let candidate = run_candidate(
        &fixture,
        proxy_address,
        witness_address,
        &local_wal,
        &candidate_store,
    );
    assert!(!candidate.status.success());
    assert!(String::from_utf8_lossy(&candidate.stderr).contains("RPO0_WRITE_REFUSED"));
    assert!(!String::from_utf8_lossy(&candidate.stdout).contains("effects=1"));
    let proxy_output = proxy.wait_with_output().expect("collect peer proxy");
    assert_success("peer proxy", &proxy_output);
    peer.kill().expect("stop isolated peer");
    witness.kill().expect("stop unused Witness");
    let _peer_status = peer.wait().expect("collect isolated peer");
    let _witness_status = witness.wait().expect("collect unused Witness");
    assert!(!peer_wal.exists());
    assert!(local_wal.is_file());
    assert_eq!(
        recover_wal(&fs::read(&local_wal).expect("read unacknowledged local WAL"))
            .expect("recover unacknowledged local WAL")
            .commit_index,
        1
    );
    assert!(!candidate_store.join("authority.journal").exists());
    assert!(!witness_store.join("authority.journal").exists());
    eprintln!(
        "scenario=6 name=ab_replication_partition seed=1 class=github-three-process-fault-proxy status=PASS single_writer_violations=0 acknowledged_write_loss=0 acknowledged_writes=0 effects=0"
    );
    fixture.cleanup();
}

#[test]
fn same_store_and_wal_candidate_race_has_at_most_one_effective_winner() {
    let fixture = Fixture::new("race");
    let peer_wal = fixture.root.join("node-b.wal");
    let local_wal = fixture.root.join("node-a.wal");
    let witness_store = fixture.root.join("witness-store");
    let candidate_store = fixture.root.join("candidate-store");
    let peer_ready = fixture.root.join("peer.ready");
    let witness_ready = fixture.root.join("witness.ready");
    let mut peer = spawn_peer(&fixture, &peer_wal, &peer_ready, 1);
    let mut witness = spawn_witness(&fixture, &witness_store, &witness_ready, 1);
    let peer_address = wait_ready(&peer_ready, &mut peer);
    let witness_address = wait_ready(&witness_ready, &mut witness);
    let first = spawn_candidate(
        &fixture,
        peer_address,
        witness_address,
        &local_wal,
        &candidate_store,
    );
    let second = spawn_candidate(
        &fixture,
        peer_address,
        witness_address,
        &local_wal,
        &candidate_store,
    );
    let first_output = first.wait_with_output().expect("collect first candidate");
    let second_output = second.wait_with_output().expect("collect second candidate");
    let outputs = [&first_output, &second_output];
    let success_count = outputs
        .iter()
        .filter(|output| output.status.success())
        .count();
    let effect_count = outputs
        .iter()
        .filter(|output| String::from_utf8_lossy(&output.stdout).contains("effects=1"))
        .count();
    if success_count != 1 {
        let _peer_kill = peer.kill();
        let _witness_kill = witness.kill();
    }
    let peer_output = peer.wait_with_output().expect("collect peer output");
    let witness_output = witness.wait_with_output().expect("collect witness output");
    assert_success("peer", &peer_output);
    assert_success("witness", &witness_output);
    assert_eq!(
        success_count, 1,
        "exactly one same-root candidate may finish"
    );
    assert_eq!(
        effect_count, 1,
        "at most one same-root test effect may appear"
    );
    let loser = outputs
        .iter()
        .find(|output| !output.status.success())
        .expect("one candidate must lose");
    let loser_stderr = String::from_utf8_lossy(&loser.stderr);
    assert!(
        loser_stderr.contains("OWNER_LOCK_REFUSED")
            || loser_stderr.contains("LAB_GENESIS_STORE_NOT_EMPTY")
            || loser_stderr.contains("LAB_GENESIS_WAL_NOT_EMPTY")
    );
    fixture.cleanup();
}

#[test]
fn candidate_and_peer_cannot_claim_two_receipts_from_one_wal_path() {
    let fixture = Fixture::new("same-wal");
    let shared_wal = fixture.root.join("shared.wal");
    let peer_ready = fixture.root.join("peer.ready");
    let candidate_store = fixture.root.join("candidate-store");
    let mut peer = spawn_peer(&fixture, &shared_wal, &peer_ready, 1);
    let peer_address = wait_ready(&peer_ready, &mut peer);
    let witness_address = SocketAddr::from_str("127.0.0.1:10").expect("parse witness fixture");
    let candidate = run_candidate(
        &fixture,
        peer_address,
        witness_address,
        &shared_wal,
        &candidate_store,
    );
    assert!(!candidate.status.success());
    assert!(String::from_utf8_lossy(&candidate.stderr).contains("OWNER_LOCK_REFUSED"));
    assert!(!String::from_utf8_lossy(&candidate.stdout).contains("effects=1"));
    peer.kill().expect("stop peer after ownership refusal");
    let peer_status = peer.wait().expect("collect stopped peer");
    assert!(!peer_status.success());
    fixture.cleanup();
}

#[test]
fn missing_witness_public_key_fails_before_state_or_network() {
    let fixture = Fixture::new("missing-key");
    fs::remove_file(&fixture.witness_public).expect("remove witness public key");
    let local_wal = fixture.root.join("node-a.wal");
    let candidate_store = fixture.root.join("candidate-store");
    let output = run_candidate(
        &fixture,
        SocketAddr::from_str("127.0.0.1:9").expect("parse peer fixture"),
        SocketAddr::from_str("127.0.0.1:10").expect("parse witness fixture"),
        &local_wal,
        &candidate_store,
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("KEY_READ_FAILED"));
    assert!(!local_wal.exists());
    assert!(!candidate_store.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("effects=1"));
    fixture.cleanup();
}

#[test]
fn duplicate_role_key_value_fails_before_state_or_network() {
    let fixture = Fixture::new("duplicate-role-key");
    fs::copy(&fixture.candidate_public, &fixture.peer_public)
        .expect("replace peer key with candidate key value");
    let local_wal = fixture.root.join("node-a.wal");
    let candidate_store = fixture.root.join("candidate-store");
    let output = run_candidate(
        &fixture,
        SocketAddr::from_str("127.0.0.1:9").expect("parse peer fixture"),
        SocketAddr::from_str("127.0.0.1:10").expect("parse witness fixture"),
        &local_wal,
        &candidate_store,
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("KEY_ROLE_ALIAS_REFUSED"));
    assert!(!local_wal.exists());
    assert!(!candidate_store.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("effects=1"));
    fixture.cleanup();
}

#[test]
fn peer_ready_file_cannot_alias_its_wal() {
    let fixture = Fixture::new("ready-wal-alias");
    let shared_path = fixture.root.join("node-b.wal");
    let output = spawn_peer(&fixture, &shared_path, &shared_path, 1)
        .wait_with_output()
        .expect("collect peer alias refusal");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PATH_ALIAS_REFUSED"));
    assert!(!shared_path.exists());
    fixture.cleanup();
}

#[test]
fn corrupt_peer_wal_never_publishes_readiness() {
    let fixture = Fixture::new("corrupt-peer");
    let peer_wal = fixture.root.join("node-b.wal");
    let peer_ready = fixture.root.join("peer.ready");
    fs::write(&peer_wal, b"not-a-canonical-wal").expect("write corrupt WAL");
    let output = spawn_peer(&fixture, &peer_wal, &peer_ready, 1)
        .wait_with_output()
        .expect("collect corrupt peer");
    assert!(!output.status.success());
    assert!(!peer_ready.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PEER_WAL_RECOVERY_REFUSED"));
    fixture.cleanup();
}

#[test]
fn one_command_self_test_runs_three_roles_and_cleans_state() {
    let root = fresh_path("one-command-clean");
    let output = Command::new(binary())
        .arg("self-test")
        .arg("--root")
        .arg(&root)
        .arg("--allow-lab-genesis")
        .output()
        .expect("run one-command self-test");
    assert_success("one-command self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("code=SELF_TEST_PASS"));
    assert!(stdout.contains("topology=three-process"));
    assert!(stdout.contains("commit_index=1"));
    assert!(stdout.contains("effects=1"));
    assert!(stdout.contains("state_retained=false"));
    assert!(
        !root.exists(),
        "successful default self-test must clean state"
    );
}

#[test]
fn one_command_self_test_can_retain_inspectable_state() {
    let root = fresh_path("one-command-keep");
    let output = Command::new(binary())
        .arg("self-test")
        .arg("--root")
        .arg(&root)
        .arg("--keep-state")
        .arg("--allow-lab-genesis")
        .output()
        .expect("run retained one-command self-test");
    assert_success("retained one-command self-test", &output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("code=SELF_TEST_PASS"));
    assert!(stdout.contains("state_retained=true"));
    assert!(root.join("node-a.wal").is_file());
    assert!(root.join("node-b.wal").is_file());
    assert!(root.join("candidate-store/authority.journal").is_file());
    assert!(root.join("witness-store/authority.journal").is_file());
    fs::remove_dir_all(root).expect("remove retained self-test state");
}

#[test]
fn self_test_requires_opt_in_and_a_new_root() {
    let missing_opt_in_root = fresh_path("self-test-missing-opt-in");
    let missing_opt_in = Command::new(binary())
        .arg("self-test")
        .arg("--root")
        .arg(&missing_opt_in_root)
        .output()
        .expect("run self-test without opt-in");
    assert!(!missing_opt_in.status.success());
    assert!(String::from_utf8_lossy(&missing_opt_in.stderr).contains("LAB_GENESIS_DISABLED"));
    assert!(!missing_opt_in_root.exists());

    let existing_root = fresh_path("self-test-existing-root");
    fs::create_dir_all(&existing_root).expect("create existing self-test root");
    let existing = Command::new(binary())
        .arg("self-test")
        .arg("--root")
        .arg(&existing_root)
        .arg("--allow-lab-genesis")
        .output()
        .expect("run self-test with existing root");
    assert!(!existing.status.success());
    assert!(String::from_utf8_lossy(&existing.stderr).contains("SELF_TEST_ROOT_REFUSED"));
    fs::remove_dir_all(existing_root).expect("remove existing self-test root");
}

#[cfg(unix)]
#[test]
fn self_test_refuses_a_symlinked_root_parent_before_writing_keys() {
    use std::os::unix::fs::symlink;

    let base = fresh_path("self-test-symlink-base");
    let target = base.join("target");
    let alias = base.join("alias");
    fs::create_dir_all(&target).expect("create self-test symlink target");
    symlink(&target, &alias).expect("create self-test parent symlink");
    let requested = alias.join("new-root");
    let output = Command::new(binary())
        .arg("self-test")
        .arg("--root")
        .arg(&requested)
        .arg("--allow-lab-genesis")
        .output()
        .expect("run self-test with symlinked parent");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PATH_SYMLINK_REFUSED"));
    assert!(!target.join("new-root").exists());
    fs::remove_dir_all(base).expect("remove self-test symlink fixture");
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_quorumarc-cluster"))
}

fn fresh_path(label: &str) -> PathBuf {
    let unique = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "quorumarc-cluster-{label}-{}-{unique}",
        std::process::id()
    ))
}

fn spawn_peer(fixture: &Fixture, wal: &Path, ready: &Path, max_connections: u64) -> Child {
    let mut command = Command::new(binary());
    command
        .arg("peer")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--wal")
        .arg(wal)
        .arg("--signing-key")
        .arg(&fixture.peer_seed)
        .arg("--candidate-public-key")
        .arg(&fixture.candidate_public)
        .arg("--max-connections")
        .arg(max_connections.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().expect("spawn peer")
}

fn spawn_witness(fixture: &Fixture, store: &Path, ready: &Path, max_connections: u64) -> Child {
    let mut command = Command::new(binary());
    command
        .arg("witness")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--store")
        .arg(store)
        .arg("--signing-key")
        .arg(&fixture.witness_seed)
        .arg("--candidate-public-key")
        .arg(&fixture.candidate_public)
        .arg("--max-connections")
        .arg(max_connections.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().expect("spawn witness")
}

fn spawn_fault_proxy(
    upstream: SocketAddr,
    ready: &Path,
    mode: &Path,
    max_connections: u64,
) -> Child {
    Command::new(binary())
        .arg("fault-proxy")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--upstream")
        .arg(upstream.to_string())
        .arg("--mode-file")
        .arg(mode)
        .arg("--max-connections")
        .arg(max_connections.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--allow-lifecycle-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn fault proxy")
}

fn spawn_candidate(
    fixture: &Fixture,
    peer: SocketAddr,
    witness: SocketAddr,
    local_wal: &Path,
    store: &Path,
) -> Child {
    let mut command = Command::new(binary());
    command
        .arg("bootstrap")
        .arg("--peer")
        .arg(peer.to_string())
        .arg("--witness")
        .arg(witness.to_string())
        .arg("--local-wal")
        .arg(local_wal)
        .arg("--store")
        .arg(store)
        .arg("--signing-key")
        .arg(&fixture.candidate_seed)
        .arg("--peer-public-key")
        .arg(&fixture.peer_public)
        .arg("--witness-public-key")
        .arg(&fixture.witness_public)
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--allow-lab-genesis")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.spawn().expect("spawn candidate")
}

fn run_candidate(
    fixture: &Fixture,
    peer: SocketAddr,
    witness: SocketAddr,
    local_wal: &Path,
    store: &Path,
) -> Output {
    spawn_candidate(fixture, peer, witness, local_wal, store)
        .wait_with_output()
        .expect("collect candidate")
}

fn wait_ready(path: &Path, child: &mut Child) -> SocketAddr {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            return SocketAddr::from_str(value.trim()).expect("parse ready address");
        }
        let status = child.try_wait().expect("inspect child status");
        assert!(status.is_none(), "service exited before readiness");
        assert!(Instant::now() < deadline, "service readiness timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_success(name: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{name} failed; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_public(path: &Path, seed: [u8; 32]) {
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let mut file = File::create(path).expect("create public key");
    file.write_all(key.as_bytes()).expect("write public key");
    file.sync_all().expect("sync public key");
}

#[cfg(unix)]
fn write_private(path: &Path, seed: [u8; 32]) {
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .expect("create private key");
    file.write_all(&seed).expect("write private key");
    file.sync_all().expect("sync private key");
}

#[cfg(not(unix))]
fn write_private(_path: &Path, _seed: [u8; 32]) {
    panic!("LAB_GENESIS_ONE_SHOT process tests require Ubuntu permissions");
}

fn lock_for_file(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path.file_name().expect("state file name").to_string_lossy();
    parent.join(format!("{name}.quorumarc.owner"))
}
