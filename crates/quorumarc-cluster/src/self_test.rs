use std::env;
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
use quorumarc_store::{DurableAuthorityStore, FileBackend};
use quorumarc_wire::SigningKey;

use crate::bootstrap::{BootstrapConfig, run_bootstrap};
use crate::path_guard::{OwnerLock, reject_symlink_components};
use crate::protocol::{
    LAB_EPOCH, LAB_INCARNATION, candidate_store_identity, witness_store_identity,
};
use crate::{ClusterError, err};

static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

const CANDIDATE_SEED: [u8; 32] = [11; 32];
const PEER_SEED: [u8; 32] = [17; 32];
const WITNESS_SEED: [u8; 32] = [29; 32];

/// Configuration for the one-command, localhost-only product self-test.
#[derive(Clone, Debug)]
pub struct SelfTestConfig {
    /// Exact cluster binary to launch for peer and Witness child roles.
    pub binary_path: PathBuf,
    /// Optional new directory. Existing paths are always refused.
    pub root_directory: Option<PathBuf>,
    /// Per-connection read/write timeout.
    pub io_timeout: Duration,
    /// Maximum time to await explicit child readiness.
    pub startup_timeout: Duration,
    /// Retain deterministic test-only state after success for inspection.
    pub keep_state: bool,
    /// Explicit acknowledgement that this exercises fixture genesis only.
    pub allow_lab_genesis: bool,
}

impl SelfTestConfig {
    /// Creates a safe default using the current executable and an ephemeral
    /// directory that is removed after a successful self-test.
    pub fn current_executable() -> Result<Self, ClusterError> {
        let binary_path = env::current_exe()
            .map_err(|error| err("SELF_TEST_BINARY_REFUSED", error.to_string()))?;
        Ok(Self {
            binary_path,
            root_directory: None,
            io_timeout: Duration::from_secs(3),
            startup_timeout: Duration::from_secs(5),
            keep_state: false,
            allow_lab_genesis: false,
        })
    }
}

/// Verified outcome of the bounded three-process self-test.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelfTestReport {
    pub reason_code: &'static str,
    pub commit_index: u64,
    pub value: u64,
    pub effect_count: usize,
    pub candidate_store_generation: u64,
    pub witness_store_generation: u64,
    pub elapsed_ms: u128,
    pub state_retained: bool,
    pub state_directory: Option<PathBuf>,
}

/// Runs a complete, bounded localhost pre-installation self-test with one
/// candidate process and separate peer and Witness children.
///
/// All key material is deterministic and public test-only material. It must
/// never be copied into an operational configuration.
pub fn run_self_test(config: SelfTestConfig) -> Result<SelfTestReport, ClusterError> {
    if !config.allow_lab_genesis {
        return Err(err(
            "LAB_GENESIS_DISABLED",
            "self-test requires explicit --allow-lab-genesis",
        ));
    }
    ensure_duration("I/O", config.io_timeout)?;
    ensure_duration("startup", config.startup_timeout)?;
    ensure_binary(&config.binary_path)?;

    let started = Instant::now();
    let root = create_root(config.root_directory.as_deref())?;
    let paths = FixturePaths::new(root.clone());
    if let Err(error) = write_fixture_keys(&paths) {
        return Err(with_root(error, &root));
    }

    let mut peer = match spawn_peer(&config, &paths) {
        Ok(child) => ChildGuard::new("peer", child),
        Err(error) => return Err(with_root(error, &root)),
    };
    let mut witness = match spawn_witness(&config, &paths) {
        Ok(child) => ChildGuard::new("witness", child),
        Err(error) => return Err(with_root(error, &root)),
    };

    let result = run_roles_and_verify(&config, &paths, &mut peer, &mut witness, started);
    let report = match result {
        Ok(report) => report,
        Err(error) => return Err(with_root(error, &root)),
    };

    if config.keep_state {
        Ok(SelfTestReport {
            state_retained: true,
            state_directory: Some(root),
            ..report
        })
    } else {
        fs::remove_dir_all(&root).map_err(|error| {
            err(
                "SELF_TEST_CLEANUP_FAILED",
                format!("{}: {error}", root.display()),
            )
        })?;
        Ok(SelfTestReport {
            state_retained: false,
            state_directory: None,
            ..report
        })
    }
}

fn run_roles_and_verify(
    config: &SelfTestConfig,
    paths: &FixturePaths,
    peer: &mut ChildGuard,
    witness: &mut ChildGuard,
    started: Instant,
) -> Result<SelfTestReport, ClusterError> {
    let peer_address = wait_ready(&paths.peer_ready, peer, config.startup_timeout)?;
    let witness_address = wait_ready(&paths.witness_ready, witness, config.startup_timeout)?;
    let bootstrap = run_bootstrap(BootstrapConfig {
        peer_address,
        witness_address,
        local_wal_path: paths.candidate_wal.clone(),
        store_directory: paths.candidate_store.clone(),
        candidate_signing_key_file: paths.candidate_seed.clone(),
        peer_public_key_file: paths.peer_public.clone(),
        witness_public_key_file: paths.witness_public.clone(),
        io_timeout: config.io_timeout,
        allow_lab_genesis: true,
    })?;
    peer.wait_success(config.startup_timeout)?;
    witness.wait_success(config.startup_timeout)?;

    if bootstrap.reason_code != "LAB_GENESIS_ONE_SHOT"
        || bootstrap.commit_index != 1
        || bootstrap.value != 1
        || bootstrap.effect_count != 1
        || bootstrap.store_generation != 4
    {
        return Err(err(
            "SELF_TEST_REPORT_REFUSED",
            "bootstrap report differs from the exact one-shot result",
        ));
    }

    let (candidate_generation, witness_generation) =
        verify_durable_outputs(paths, bootstrap.state_root, bootstrap.promotion_digest)?;
    Ok(SelfTestReport {
        reason_code: "SELF_TEST_PASS",
        commit_index: bootstrap.commit_index,
        value: bootstrap.value,
        effect_count: bootstrap.effect_count,
        candidate_store_generation: candidate_generation,
        witness_store_generation: witness_generation,
        elapsed_ms: started.elapsed().as_millis(),
        state_retained: false,
        state_directory: None,
    })
}

fn ensure_duration(label: &str, duration: Duration) -> Result<(), ClusterError> {
    if duration.is_zero() {
        return Err(err(
            "SELF_TEST_CONFIG_REFUSED",
            format!("{label} timeout is zero"),
        ));
    }
    let _milliseconds = u64::try_from(duration.as_millis()).map_err(|_| {
        err(
            "SELF_TEST_CONFIG_REFUSED",
            format!("{label} timeout exceeds u64 milliseconds"),
        )
    })?;
    Ok(())
}

fn ensure_binary(path: &Path) -> Result<(), ClusterError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        err(
            "SELF_TEST_BINARY_REFUSED",
            format!("{}: {error}", path.display()),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(err(
            "SELF_TEST_BINARY_REFUSED",
            format!("{} is not a regular non-symlink file", path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn create_root(requested: Option<&Path>) -> Result<PathBuf, ClusterError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let create = |path: &Path| -> Result<PathBuf, std::io::Error> {
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        builder.create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        Ok(path.to_path_buf())
    };

    if let Some(path) = requested {
        reject_symlink_components(path)?;
        return create(path).map_err(|error| {
            err(
                "SELF_TEST_ROOT_REFUSED",
                format!("{} must be a new directory: {error}", path.display()),
            )
        });
    }

    for _ in 0..32 {
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let path = env::temp_dir().join(format!(
            "quorumarc-self-test-{}-{sequence}",
            std::process::id()
        ));
        reject_symlink_components(&path)?;
        match create(&path) {
            Ok(created) => return Ok(created),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(err(
                    "SELF_TEST_ROOT_REFUSED",
                    format!("{}: {error}", path.display()),
                ));
            }
        }
    }
    Err(err(
        "SELF_TEST_ROOT_REFUSED",
        "unable to allocate a unique test directory",
    ))
}

#[cfg(not(unix))]
fn create_root(_requested: Option<&Path>) -> Result<PathBuf, ClusterError> {
    Err(err(
        "SELF_TEST_UNSUPPORTED",
        "the permission-checked self-test requires Ubuntu/Linux",
    ))
}

fn with_root(error: ClusterError, root: &Path) -> ClusterError {
    err(
        error.reason_code(),
        format!("{}; retained_state={}", error.detail(), root.display()),
    )
}

#[derive(Clone, Debug)]
struct FixturePaths {
    root: PathBuf,
    candidate_seed: PathBuf,
    peer_seed: PathBuf,
    witness_seed: PathBuf,
    candidate_public: PathBuf,
    peer_public: PathBuf,
    witness_public: PathBuf,
    candidate_wal: PathBuf,
    peer_wal: PathBuf,
    candidate_store: PathBuf,
    witness_store: PathBuf,
    peer_ready: PathBuf,
    witness_ready: PathBuf,
}

impl FixturePaths {
    fn new(root: PathBuf) -> Self {
        Self {
            candidate_seed: root.join("node-a.seed"),
            peer_seed: root.join("node-b.seed"),
            witness_seed: root.join("witness.seed"),
            candidate_public: root.join("node-a.public"),
            peer_public: root.join("node-b.public"),
            witness_public: root.join("witness.public"),
            candidate_wal: root.join("node-a.wal"),
            peer_wal: root.join("node-b.wal"),
            candidate_store: root.join("candidate-store"),
            witness_store: root.join("witness-store"),
            peer_ready: root.join("peer.ready"),
            witness_ready: root.join("witness.ready"),
            root,
        }
    }
}

fn write_fixture_keys(paths: &FixturePaths) -> Result<(), ClusterError> {
    write_private(&paths.candidate_seed, CANDIDATE_SEED)?;
    write_private(&paths.peer_seed, PEER_SEED)?;
    write_private(&paths.witness_seed, WITNESS_SEED)?;
    write_public(&paths.candidate_public, CANDIDATE_SEED)?;
    write_public(&paths.peer_public, PEER_SEED)?;
    write_public(&paths.witness_public, WITNESS_SEED)?;
    File::open(&paths.root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))
}

#[cfg(unix)]
fn write_private(path: &Path, seed: [u8; 32]) -> Result<(), ClusterError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))?;
    file.write_all(&seed)
        .and_then(|()| file.sync_all())
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))
}

#[cfg(not(unix))]
fn write_private(_path: &Path, _seed: [u8; 32]) -> Result<(), ClusterError> {
    Err(err(
        "SELF_TEST_UNSUPPORTED",
        "private key permissions require Ubuntu/Linux",
    ))
}

fn write_public(path: &Path, seed: [u8; 32]) -> Result<(), ClusterError> {
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))?;
    file.write_all(key.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| err("SELF_TEST_KEY_WRITE_FAILED", error.to_string()))
}

fn spawn_peer(config: &SelfTestConfig, paths: &FixturePaths) -> Result<Child, ClusterError> {
    let timeout = duration_millis(config.io_timeout)?;
    Command::new(&config.binary_path)
        .arg("peer")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(&paths.peer_ready)
        .arg("--wal")
        .arg(&paths.peer_wal)
        .arg("--signing-key")
        .arg(&paths.peer_seed)
        .arg("--candidate-public-key")
        .arg(&paths.candidate_public)
        .arg("--max-connections")
        .arg("1")
        .arg("--timeout-ms")
        .arg(timeout.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| err("SELF_TEST_PEER_SPAWN_FAILED", error.to_string()))
}

fn spawn_witness(config: &SelfTestConfig, paths: &FixturePaths) -> Result<Child, ClusterError> {
    let timeout = duration_millis(config.io_timeout)?;
    Command::new(&config.binary_path)
        .arg("witness")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--ready-file")
        .arg(&paths.witness_ready)
        .arg("--store")
        .arg(&paths.witness_store)
        .arg("--signing-key")
        .arg(&paths.witness_seed)
        .arg("--candidate-public-key")
        .arg(&paths.candidate_public)
        .arg("--max-connections")
        .arg("1")
        .arg("--timeout-ms")
        .arg(timeout.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| err("SELF_TEST_WITNESS_SPAWN_FAILED", error.to_string()))
}

fn duration_millis(duration: Duration) -> Result<u64, ClusterError> {
    u64::try_from(duration.as_millis()).map_err(|_| {
        err(
            "SELF_TEST_CONFIG_REFUSED",
            "timeout exceeds u64 milliseconds",
        )
    })
}

fn wait_ready(
    path: &Path,
    child: &mut ChildGuard,
    timeout: Duration,
) -> Result<SocketAddr, ClusterError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| err("SELF_TEST_CONFIG_REFUSED", "startup deadline overflow"))?;
    loop {
        match fs::read_to_string(path) {
            Ok(value) => {
                let address = SocketAddr::from_str(value.trim()).map_err(|error| {
                    err(
                        "SELF_TEST_READY_REFUSED",
                        format!("{}: {error}", path.display()),
                    )
                })?;
                if !address.ip().is_loopback() {
                    return Err(err(
                        "SELF_TEST_READY_REFUSED",
                        format!("{} published non-loopback {address}", child.name),
                    ));
                }
                return Ok(address);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(err(
                    "SELF_TEST_READY_REFUSED",
                    format!("{}: {error}", path.display()),
                ));
            }
        }
        if let Some(status) = child.try_wait()? {
            return Err(err(
                "SELF_TEST_CHILD_EARLY_EXIT",
                format!("{} exited before readiness with {status}", child.name),
            ));
        }
        if Instant::now() >= deadline {
            return Err(err(
                "SELF_TEST_READY_TIMEOUT",
                format!("{} did not publish readiness", child.name),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn verify_durable_outputs(
    paths: &FixturePaths,
    expected_state_root: [u8; 32],
    expected_promotion_digest: [u8; 32],
) -> Result<(u64, u64), ClusterError> {
    let candidate_bytes = fs::read(&paths.candidate_wal)
        .map_err(|error| err("SELF_TEST_WAL_REFUSED", error.to_string()))?;
    let peer_bytes = fs::read(&paths.peer_wal)
        .map_err(|error| err("SELF_TEST_WAL_REFUSED", error.to_string()))?;
    if candidate_bytes != peer_bytes {
        return Err(err(
            "SELF_TEST_WAL_REFUSED",
            "candidate and peer durable WAL bytes differ",
        ));
    }
    let recovered = recover_wal(&candidate_bytes)
        .map_err(|error| err("SELF_TEST_WAL_REFUSED", error.to_string()))?;
    if recovered.commit_index != 1
        || recovered.value != 1
        || recovered.state_root != expected_state_root
    {
        return Err(err(
            "SELF_TEST_WAL_REFUSED",
            "recovered RPO-0 state differs from acknowledged state",
        ));
    }

    let candidate = DurableAuthorityStore::open_in(
        &paths.candidate_store,
        candidate_store_identity()?,
        FileBackend,
    )
    .map_err(|error| err("SELF_TEST_STORE_REFUSED", error.to_string()))?;
    let witness = DurableAuthorityStore::open_in(
        &paths.witness_store,
        witness_store_identity()?,
        FileBackend,
    )
    .map_err(|error| err("SELF_TEST_STORE_REFUSED", error.to_string()))?;
    let activation = candidate.state().activation_receipt().ok_or_else(|| {
        err(
            "SELF_TEST_STORE_REFUSED",
            "candidate activation receipt is missing",
        )
    })?;
    if candidate.generation() != 4
        || candidate.state().highest_epoch() != LAB_EPOCH
        || candidate.state().incarnation() != LAB_INCARNATION
        || activation.epoch() != LAB_EPOCH
        || activation.promotion_digest() != &expected_promotion_digest
        || witness.generation() != 1
        || witness.state().highest_epoch() != LAB_EPOCH
    {
        return Err(err(
            "SELF_TEST_STORE_REFUSED",
            "durable authority state differs from the exact self-test result",
        ));
    }
    verify_locks_released(paths)?;
    Ok((candidate.generation(), witness.generation()))
}

fn verify_locks_released(paths: &FixturePaths) -> Result<(), ClusterError> {
    let candidate = OwnerLock::for_store(&paths.candidate_store, "self-test-verifier")
        .map_err(|error| err("SELF_TEST_LOCK_REFUSED", error.to_string()))?;
    drop(candidate);
    let witness = OwnerLock::for_store(&paths.witness_store, "self-test-verifier")
        .map_err(|error| err("SELF_TEST_LOCK_REFUSED", error.to_string()))?;
    drop(witness);
    let node_a = OwnerLock::for_file(&paths.candidate_wal, "self-test-verifier")
        .map_err(|error| err("SELF_TEST_LOCK_REFUSED", error.to_string()))?;
    drop(node_a);
    let node_b = OwnerLock::for_file(&paths.peer_wal, "self-test-verifier")
        .map_err(|error| err("SELF_TEST_LOCK_REFUSED", error.to_string()))?;
    drop(node_b);
    Ok(())
}

struct ChildGuard {
    name: &'static str,
    child: Option<Child>,
}

impl ChildGuard {
    const fn new(name: &'static str, child: Child) -> Self {
        Self {
            name,
            child: Some(child),
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, ClusterError> {
        self.child
            .as_mut()
            .ok_or_else(|| err("SELF_TEST_CHILD_REFUSED", "child already collected"))
    }

    fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>, ClusterError> {
        let name = self.name;
        self.child_mut()?
            .try_wait()
            .map_err(|error| err("SELF_TEST_CHILD_REFUSED", format!("{name}: {error}")))
    }

    fn wait_success(&mut self, timeout: Duration) -> Result<(), ClusterError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| err("SELF_TEST_CONFIG_REFUSED", "child exit deadline overflow"))?;
        loop {
            if self.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(err(
                    "SELF_TEST_CHILD_EXIT_TIMEOUT",
                    format!("{} did not exit after its bounded request", self.name),
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
        let child = self
            .child
            .take()
            .ok_or_else(|| err("SELF_TEST_CHILD_REFUSED", "child already collected"))?;
        let output = child
            .wait_with_output()
            .map_err(|error| err("SELF_TEST_CHILD_REFUSED", format!("{}: {error}", self.name)))?;
        if !output.status.success() {
            return Err(child_output_error(self.name, &output));
        }
        Ok(())
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _kill_result = child.kill();
            }
        }
        let _wait_result = child.wait();
    }
}

fn child_output_error(name: &str, output: &Output) -> ClusterError {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    err(
        "SELF_TEST_CHILD_REFUSED",
        format!(
            "{name} exited {}; stdout={stdout} stderr={stderr}",
            output.status
        ),
    )
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn child_exit_wait_is_bounded_and_typed() {
        let child = Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn sleeping child");
        let mut guard = ChildGuard::new("sleeping-test-child", child);
        let error = guard
            .wait_success(Duration::from_millis(20))
            .expect_err("non-terminating child must time out");
        assert_eq!(error.reason_code(), "SELF_TEST_CHILD_EXIT_TIMEOUT");
    }
}
