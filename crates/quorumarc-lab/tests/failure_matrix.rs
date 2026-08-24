use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
use std::time::Duration;

use quorumarc_core::{
    EffectGate, Epoch, GateError, GateRecoveryState, GateState, Incarnation, NodeId, PolicyHash,
    TrustedClock, WorkloadId,
};
use quorumarc_lab::{
    ClientError, DecisionCode, RequestId, TEST_KEY_ID, TEST_POLICY_HASH, TestPeerKeys,
    VoteRequest, VoteResponse, lab_binding, request_vote,
};
use quorumarc_runtime::{EffectEmitError, TestEffectActor};
use quorumarc_wire::CanonicalId;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECT_REFUSAL_SEED: u8 = 101;
const DUPLICATE_REQUEST_SEED: u8 = 103;
const DELAYED_EPOCH_SEED: u8 = 107;
const SIMULTANEOUS_CANDIDATE_SEED: u8 = 109;
#[cfg(target_os = "linux")]
const PROCESS_PAUSE_SEED: u8 = 113;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(trace: &str, seed: u8) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-lab-{trace}-seed-{seed}-{}-{sequence}",
            std::process::id()
        ));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

struct WitnessChild {
    child: Option<Child>,
    address: SocketAddr,
}

impl WitnessChild {
    fn spawn(directory: &TestDirectory) -> io::Result<Self> {
        let ready_file = directory.path().join("witness.ready");
        match fs::remove_file(&ready_file) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let store = directory.path().join("store");
        let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-lab"))
            .arg("witness")
            .arg("--store")
            .arg(store)
            .arg("--ready-file")
            .arg(&ready_file)
            .arg("--listen")
            .arg("127.0.0.1:0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        for _ in 0..250 {
            match fs::read_to_string(&ready_file) {
                Ok(text) => {
                    let address = SocketAddr::from_str(text.trim()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid witness ready address")
                    })?;
                    return Ok(Self {
                        child: Some(child),
                        address,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            if child.try_wait()?.is_some() {
                return Err(io::Error::other("witness exited before readiness"));
            }
            thread::sleep(Duration::from_millis(20));
        }
        let _kill_result = child.kill();
        let _wait_result = child.wait();
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "witness readiness timed out",
        ))
    }

    const fn address(&self) -> SocketAddr {
        self.address
    }

    fn kill_and_wait(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error),
            }
            let _status = child.wait()?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn signal(&self, signal: &str) -> io::Result<()> {
        let child = self
            .child
            .as_ref()
            .ok_or_else(|| io::Error::other("witness process is not running"))?;
        let status = Command::new("kill")
            .arg(signal)
            .arg(child.id().to_string())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other("process signal command failed"))
        }
    }
}

impl Drop for WitnessChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _kill_result = child.kill();
            let _wait_result = child.wait();
        }
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl TrustedClock for FixedClock {
    fn now_ms(&self) -> u64 {
        10_250
    }
}

fn value_or_abort<T, E>(result: Result<T, E>) -> T {
    let Ok(value) = result else {
        std::process::abort();
    };
    value
}

fn signed_request(candidate: &str, epoch: u64, trace_seed: u8) -> VoteRequest {
    let candidate_id = value_or_abort(CanonicalId::new(candidate));
    let Some(signing_key) = TestPeerKeys::candidate_signing_key(&candidate_id) else {
        std::process::abort();
    };
    value_or_abort(VoteRequest::sign(
        value_or_abort(RequestId::new([trace_seed; 16])),
        value_or_abort(lab_binding(candidate, epoch, trace_seed)),
        value_or_abort(CanonicalId::new(TEST_KEY_ID)),
        &signing_key,
    ))
}

fn assert_response_cannot_open_effects(trace_seed: u8, epoch: u64) {
    let gate = EffectGate::recover(
        value_or_abort(NodeId::new("node-a")),
        value_or_abort(WorkloadId::new("orders")),
        PolicyHash::new(TEST_POLICY_HASH),
        GateRecoveryState::new(Epoch(0), Incarnation(7), 10_000),
        FixedClock,
    );
    let mut effects = TestEffectActor::new(gate);
    assert_eq!(
        effects.emit(
            [trace_seed; 16],
            value_or_abort(NodeId::new("node-a")),
            Epoch(epoch),
            b"must-remain-blocked",
        ),
        Err(EffectEmitError::Gate(GateError::GateClosed))
    );
    assert_eq!(effects.records().len(), 0);
    assert_eq!(
        effects.gate_state(),
        &GateState::Closed {
            last_epoch: Epoch(0)
        }
    );
}

fn concurrent_vote_pair(
    address: SocketAddr,
    first: VoteRequest,
    second: VoteRequest,
) -> [VoteResponse; 2] {
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_handle = thread::spawn(move || {
        first_barrier.wait();
        request_vote(address, &first, IO_TIMEOUT)
    });
    let second_barrier = Arc::clone(&barrier);
    let second_handle = thread::spawn(move || {
        second_barrier.wait();
        request_vote(address, &second, IO_TIMEOUT)
    });
    barrier.wait();
    [
        value_or_abort(value_or_abort(first_handle.join())),
        value_or_abort(value_or_abort(second_handle.join())),
    ]
}

#[test]
fn trace_s101_witness_connection_refusal_keeps_authority_and_effects_closed() {
    let directory = value_or_abort(TestDirectory::new(
        "witness-unavailable",
        CONNECT_REFUSAL_SEED,
    ));
    let mut witness = value_or_abort(WitnessChild::spawn(&directory));
    let unavailable_address = witness.address();
    value_or_abort(witness.kill_and_wait());
    let request = signed_request("node-a", 31, CONNECT_REFUSAL_SEED);

    let result = request_vote(unavailable_address, &request, Duration::from_millis(500));
    assert!(matches!(
        result,
        Err(ClientError::Io {
            kind: io::ErrorKind::ConnectionRefused,
            ..
        })
    ));
    assert_response_cannot_open_effects(CONNECT_REFUSAL_SEED, 31);
}

#[test]
fn trace_s103_simultaneous_duplicate_stable_request_is_idempotent_without_authority() {
    let directory = value_or_abort(TestDirectory::new(
        "duplicate-request",
        DUPLICATE_REQUEST_SEED,
    ));
    let witness = value_or_abort(WitnessChild::spawn(&directory));
    let request = signed_request("node-a", 33, DUPLICATE_REQUEST_SEED);

    let responses = concurrent_vote_pair(witness.address(), request.clone(), request);
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.code() == DecisionCode::GrantedDurablyRecorded)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.code() == DecisionCode::GrantedAlreadyDurable)
            .count(),
        1
    );
    assert!(
        responses
            .iter()
            .all(|response| response.durable_generation() == Some(1))
    );
    assert_eq!(responses[0].vote(), responses[1].vote());
    assert_response_cannot_open_effects(DUPLICATE_REQUEST_SEED, 33);
}

#[test]
fn trace_s107_delayed_old_epoch_after_newer_durable_vote_is_refused_without_authority() {
    let directory = value_or_abort(TestDirectory::new("delayed-epoch", DELAYED_EPOCH_SEED));
    let witness = value_or_abort(WitnessChild::spawn(&directory));
    let current = signed_request("node-a", 52, DELAYED_EPOCH_SEED);
    let stale = signed_request("node-a", 51, DELAYED_EPOCH_SEED.saturating_add(1));
    let address = witness.address();
    let (release_sender, release_receiver) = mpsc::channel();
    let delayed_handle = thread::spawn(move || {
        value_or_abort(release_receiver.recv());
        request_vote(address, &stale, IO_TIMEOUT)
    });

    let current_response = value_or_abort(request_vote(witness.address(), &current, IO_TIMEOUT));
    assert_eq!(
        current_response.code(),
        DecisionCode::GrantedDurablyRecorded
    );
    assert_eq!(current_response.durable_generation(), Some(1));
    value_or_abort(release_sender.send(()));
    let stale_response = value_or_abort(value_or_abort(delayed_handle.join()));
    assert_eq!(stale_response.code(), DecisionCode::RefusedStaleEpoch);
    assert_eq!(stale_response.durable_generation(), None);
    assert!(stale_response.vote().is_none());
    assert_response_cannot_open_effects(DELAYED_EPOCH_SEED, 52);
}

#[test]
fn trace_s109_simultaneous_same_epoch_candidates_record_exactly_one_durable_grant() {
    let directory = value_or_abort(TestDirectory::new(
        "same-epoch-candidates",
        SIMULTANEOUS_CANDIDATE_SEED,
    ));
    let mut first_witness = value_or_abort(WitnessChild::spawn(&directory));
    let node_a = signed_request("node-a", 61, SIMULTANEOUS_CANDIDATE_SEED);
    let node_b = signed_request(
        "node-b",
        61,
        SIMULTANEOUS_CANDIDATE_SEED.saturating_add(1),
    );

    let responses = concurrent_vote_pair(first_witness.address(), node_a.clone(), node_b.clone());
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.code() == DecisionCode::GrantedDurablyRecorded)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.code() == DecisionCode::RefusedConflictSameEpoch)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.durable_generation() == Some(1))
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.vote().is_some())
            .count(),
        1
    );

    let (winner, loser) = if responses[0].code() == DecisionCode::GrantedDurablyRecorded {
        (&node_a, &node_b)
    } else {
        (&node_b, &node_a)
    };
    value_or_abort(first_witness.kill_and_wait());
    let second_witness = value_or_abort(WitnessChild::spawn(&directory));
    assert_eq!(
        value_or_abort(request_vote(second_witness.address(), winner, IO_TIMEOUT)).code(),
        DecisionCode::GrantedAlreadyDurable
    );
    let loser_after_restart =
        value_or_abort(request_vote(second_witness.address(), loser, IO_TIMEOUT));
    assert_eq!(
        loser_after_restart.code(),
        DecisionCode::RefusedConflictSameEpoch
    );
    assert!(loser_after_restart.vote().is_none());
    assert_response_cannot_open_effects(SIMULTANEOUS_CANDIDATE_SEED, 61);
}

#[cfg(target_os = "linux")]
#[test]
fn trace_s113_witness_process_pause_resume_returns_only_vote_evidence_without_authority() {
    let directory = value_or_abort(TestDirectory::new("process-pause", PROCESS_PAUSE_SEED));
    let witness = value_or_abort(WitnessChild::spawn(&directory));
    let request = signed_request("node-a", 71, PROCESS_PAUSE_SEED);
    value_or_abort(witness.signal("-STOP"));
    let address = witness.address();
    let request_handle =
        thread::spawn(move || request_vote(address, &request, Duration::from_secs(3)));

    thread::sleep(Duration::from_millis(100));
    assert!(!request_handle.is_finished());
    value_or_abort(witness.signal("-CONT"));
    let response = value_or_abort(value_or_abort(request_handle.join()));
    assert_eq!(response.code(), DecisionCode::GrantedDurablyRecorded);
    assert_eq!(response.durable_generation(), Some(1));
    assert!(response.vote().is_some());
    assert_response_cannot_open_effects(PROCESS_PAUSE_SEED, 71);
}
