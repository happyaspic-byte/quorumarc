#![cfg(unix)]
#![allow(clippy::expect_used, clippy::panic)]

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use quorumarc_rpo0::recover_wal;
use quorumarc_wire::SigningKey;

static NEXT: AtomicU64 = AtomicU64::new(1);
const TIMEOUT: Duration = Duration::from_secs(15);

struct Fixture {
    root: PathBuf,
    client_seed: PathBuf,
    primary_seed: PathBuf,
    replica_seed: PathBuf,
    client_public: PathBuf,
    primary_public: PathBuf,
    replica_public: PathBuf,
    primary_wal: PathBuf,
    replica_wal: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "quorumarc-continuous-{label}-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("create continuous fixture");
        let fixture = Self {
            client_seed: root.join("client.seed"),
            primary_seed: root.join("primary.seed"),
            replica_seed: root.join("replica.seed"),
            client_public: root.join("client.public"),
            primary_public: root.join("primary.public"),
            replica_public: root.join("replica.public"),
            primary_wal: root.join("primary.wal"),
            replica_wal: root.join("replica.wal"),
            root,
        };
        write_private(&fixture.client_seed, [41; 32]);
        write_private(&fixture.primary_seed, [43; 32]);
        write_private(&fixture.replica_seed, [47; 32]);
        write_public(&fixture.client_public, [41; 32]);
        write_public(&fixture.primary_public, [43; 32]);
        write_public(&fixture.replica_public, [47; 32]);
        fixture
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn live_client_ack_requires_two_process_durable_copies_and_exact_retry_is_stable() {
    let fixture = Fixture::new("ack");
    let replica_ready = fixture.root.join("replica.ready");
    let primary_ready = fixture.root.join("primary.ready");
    let mut replica = spawn_replica(&fixture, &replica_ready, 3);
    let replica_address = wait_ready(&replica_ready, &mut replica);
    let mut primary = spawn_primary(&fixture, &primary_ready, replica_address, 5);
    let primary_address = wait_ready(&primary_ready, &mut primary);

    let first = submit(&fixture, primary_address, 73, 0, 3);
    assert_success("first submit", &first);
    let first_stdout = String::from_utf8_lossy(&first.stdout);
    assert!(first_stdout.contains("code=CONTINUOUS_ACKNOWLEDGED"));
    assert!(first_stdout.contains("operation_id=49494949494949494949494949494949"));
    assert!(first_stdout.contains("commit_index=1"));
    assert!(first_stdout.contains("value=3"));

    let retry = submit(&fixture, primary_address, 73, 0, 3);
    assert_success("exact retry", &retry);
    assert!(String::from_utf8_lossy(&retry.stdout).contains("commit_index=1"));
    assert!(String::from_utf8_lossy(&retry.stdout).contains("value=3"));

    let second = submit(&fixture, primary_address, 83, 1, 4);
    assert_success("second fresh submit", &second);
    assert!(String::from_utf8_lossy(&second.stdout).contains("commit_index=2"));
    assert!(String::from_utf8_lossy(&second.stdout).contains("value=7"));

    let conflicting = submit(&fixture, primary_address, 73, 0, 9);
    assert!(!conflicting.status.success());
    assert!(String::from_utf8_lossy(&conflicting.stdout).contains("code=CONTINUOUS_REFUSED"));
    let zero = submit(&fixture, primary_address, 93, 2, 0);
    assert!(!zero.status.success());
    assert!(String::from_utf8_lossy(&zero.stdout).contains("code=CONTINUOUS_REFUSED"));

    let primary_output = primary.wait_with_output().expect("collect primary");
    let replica_output = replica.wait_with_output().expect("collect replica");
    assert_success("continuous primary", &primary_output);
    assert_success("continuous replica", &replica_output);

    let primary_bytes = fs::read(&fixture.primary_wal).expect("read primary WAL");
    let replica_bytes = fs::read(&fixture.replica_wal).expect("read replica WAL");
    assert_eq!(primary_bytes, replica_bytes);
    let recovered = recover_wal(&primary_bytes).expect("recover continuous WAL");
    assert_eq!(recovered.commit_index, 2);
    assert_eq!(recovered.value, 7);
    eprintln!(
        "scenario=20 name=live_continuous_two_copy_ack seed=1 class=github-process-continuous-rpo0 status=PASS submitted=3 acknowledged=3 refused=0 unknown=0 acknowledged_write_loss=0 duplicate_applications=0"
    );
}

#[test]
fn reachable_lagging_replica_prevents_primary_append() {
    let fixture = Fixture::new("lagging");
    let seeded = quorumarc_rpo0::WalEntry {
        commit_index: 1,
        operation_id: quorumarc_rpo0::OperationId::new([99; 16]),
        previous_value: 0,
        increment: 2,
        value: 2,
    };
    fs::write(&fixture.replica_wal, seeded.encode()).expect("seed lagging-test replica WAL");
    let replica_ready = fixture.root.join("replica.ready");
    let primary_ready = fixture.root.join("primary.ready");
    let mut replica = spawn_replica(&fixture, &replica_ready, 1);
    let replica_address = wait_ready(&replica_ready, &mut replica);
    let mut primary = spawn_primary(&fixture, &primary_ready, replica_address, 1);
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Some(status) = primary.try_wait().expect("inspect mismatched primary") {
            assert!(!status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "mismatched primary did not refuse readiness"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let replica_output = replica.wait_with_output().expect("collect lagging replica");
    assert_success("lagging replica", &replica_output);
    assert!(!primary_ready.exists());
    assert!(!fixture.primary_wal.exists());
}

#[test]
fn equal_wal_restart_rebuilds_exact_retry_without_duplicate_append() {
    let fixture = Fixture::new("restart-dedupe");
    let replica_ready = fixture.root.join("replica.ready");
    let primary_ready = fixture.root.join("primary.ready");
    let mut replica = spawn_replica(&fixture, &replica_ready, 2);
    let replica_address = wait_ready(&replica_ready, &mut replica);
    let mut primary = spawn_primary(&fixture, &primary_ready, replica_address, 1);
    let primary_address = wait_ready(&primary_ready, &mut primary);
    let first = submit(&fixture, primary_address, 101, 0, 6);
    assert_success("restart seed submit", &first);
    assert_success(
        "restart seed primary",
        &primary.wait_with_output().expect("collect first primary"),
    );
    assert_success(
        "restart seed replica",
        &replica.wait_with_output().expect("collect first replica"),
    );
    let original_primary = fs::read(&fixture.primary_wal).expect("read first primary WAL");
    let original_replica = fs::read(&fixture.replica_wal).expect("read first replica WAL");
    assert_eq!(original_primary, original_replica);
    fs::remove_file(&replica_ready).expect("remove first replica readiness");
    fs::remove_file(&primary_ready).expect("remove first primary readiness");

    let mut restarted_replica = spawn_replica(&fixture, &replica_ready, 1);
    let restarted_replica_address = wait_ready(&replica_ready, &mut restarted_replica);
    let mut restarted_primary =
        spawn_primary(&fixture, &primary_ready, restarted_replica_address, 1);
    let restarted_primary_address = wait_ready(&primary_ready, &mut restarted_primary);
    let retry = submit(&fixture, restarted_primary_address, 101, 0, 6);
    assert_success("restart exact retry", &retry);
    assert!(String::from_utf8_lossy(&retry.stdout).contains("commit_index=1"));
    assert!(String::from_utf8_lossy(&retry.stdout).contains("value=6"));
    assert_success(
        "restarted primary",
        &restarted_primary
            .wait_with_output()
            .expect("collect restarted primary"),
    );
    assert_success(
        "restarted replica",
        &restarted_replica
            .wait_with_output()
            .expect("collect restarted replica"),
    );
    assert_eq!(
        fs::read(&fixture.primary_wal).expect("read restarted primary WAL"),
        original_primary
    );
    assert_eq!(
        fs::read(&fixture.replica_wal).expect("read restarted replica WAL"),
        original_replica
    );
}

#[test]
fn peer_loss_after_readiness_returns_unknown_and_never_acknowledges_one_copy() {
    let fixture = Fixture::new("peer-loss");
    let replica_ready = fixture.root.join("replica.ready");
    let primary_ready = fixture.root.join("primary.ready");
    let mut replica = spawn_replica(&fixture, &replica_ready, 1);
    let replica_address = wait_ready(&replica_ready, &mut replica);
    let mut primary = spawn_primary(&fixture, &primary_ready, replica_address, 1);
    let primary_address = wait_ready(&primary_ready, &mut primary);
    let replica_output = replica
        .wait_with_output()
        .expect("collect startup-only replica");
    assert_success("startup-only replica", &replica_output);

    let submit = submit(&fixture, primary_address, 79, 0, 1);
    assert!(!submit.status.success());
    assert!(String::from_utf8_lossy(&submit.stdout).contains("code=CONTINUOUS_UNKNOWN"));
    assert!(!String::from_utf8_lossy(&submit.stdout).contains("CONTINUOUS_ACKNOWLEDGED"));
    let primary_output = primary
        .wait_with_output()
        .expect("collect peer-loss primary");
    assert_success("peer-loss primary", &primary_output);
    assert!(!fixture.primary_wal.exists());
    assert!(!fixture.replica_wal.exists());
    eprintln!(
        "scenario=6 name=live_continuous_peer_loss seed=1 class=github-process-continuous-rpo0 status=PASS submitted=1 acknowledged=0 refused=0 unknown=1 acknowledged_write_loss=0"
    );
}

fn spawn_replica(fixture: &Fixture, ready: &Path, max_connections: u64) -> Child {
    Command::new(binary())
        .arg("continuous-replica")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--wal")
        .arg(&fixture.replica_wal)
        .arg("--signing-key")
        .arg(&fixture.replica_seed)
        .arg("--primary-public-key")
        .arg(&fixture.primary_public)
        .arg("--max-connections")
        .arg(max_connections.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--policy-byte")
        .arg("165")
        .arg("--allow-continuous-rpo0-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn continuous replica")
}

fn spawn_primary(
    fixture: &Fixture,
    ready: &Path,
    replica_address: SocketAddr,
    max_connections: u64,
) -> Child {
    Command::new(binary())
        .arg("continuous-primary")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(ready)
        .arg("--wal")
        .arg(&fixture.primary_wal)
        .arg("--signing-key")
        .arg(&fixture.primary_seed)
        .arg("--client-public-key")
        .arg(&fixture.client_public)
        .arg("--replica-public-key")
        .arg(&fixture.replica_public)
        .arg("--replica")
        .arg(replica_address.to_string())
        .arg("--max-connections")
        .arg(max_connections.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--policy-byte")
        .arg("165")
        .arg("--allow-continuous-rpo0-lab")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn continuous primary")
}

fn submit(
    fixture: &Fixture,
    primary_address: SocketAddr,
    operation_byte: u8,
    expected_commit: u64,
    increment: u64,
) -> Output {
    Command::new(binary())
        .arg("continuous-submit")
        .arg("--primary")
        .arg(primary_address.to_string())
        .arg("--primary-public-key")
        .arg(&fixture.primary_public)
        .arg("--client-signing-key")
        .arg(&fixture.client_seed)
        .arg("--operation-byte")
        .arg(operation_byte.to_string())
        .arg("--expected-commit")
        .arg(expected_commit.to_string())
        .arg("--increment")
        .arg(increment.to_string())
        .arg("--timeout-ms")
        .arg("3000")
        .arg("--policy-byte")
        .arg("165")
        .arg("--allow-continuous-rpo0-lab")
        .output()
        .expect("run continuous submit")
}

fn wait_ready(path: &Path, child: &mut Child) -> SocketAddr {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Ok(value) = fs::read_to_string(path) {
            if let Ok(address) = SocketAddr::from_str(value.trim()) {
                return address;
            }
        }
        assert!(
            child.try_wait().expect("inspect service").is_none(),
            "service exited before readiness"
        );
        assert!(Instant::now() < deadline, "service readiness timed out");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_quorumarc-cluster"))
}

fn assert_success(label: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{label} failed\nstdout:\n{}\nstderr:\n{}",
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
