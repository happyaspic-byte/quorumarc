use std::fs;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use quorumarc_lab::{
    DecisionCode, MAX_LAB_FRAME_SIZE, ProtocolError, RequestId, TEST_KEY_ID, TestPeerKeys,
    VoteRequest, VoteResponse, lab_binding, request_vote,
};
use quorumarc_runtime::FrameCodec;
use quorumarc_wire::CanonicalId;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-lab-{label}-{}-{sequence}",
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
}

impl Drop for WitnessChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _kill_result = child.kill();
            let _wait_result = child.wait();
        }
    }
}

fn value_or_abort<T, E>(result: Result<T, E>) -> T {
    let Ok(value) = result else {
        std::process::abort();
    };
    value
}

fn signed_request(
    candidate: &str,
    epoch: u64,
    message_byte: u8,
    request_byte: u8,
) -> VoteRequest {
    let candidate_id = value_or_abort(CanonicalId::new(candidate));
    let Some(signing_key) = TestPeerKeys::candidate_signing_key(&candidate_id) else {
        std::process::abort();
    };
    value_or_abort(VoteRequest::sign(
        value_or_abort(RequestId::new([request_byte; 16])),
        value_or_abort(lab_binding(candidate, epoch, message_byte)),
        value_or_abort(CanonicalId::new(TEST_KEY_ID)),
        &signing_key,
    ))
}

#[test]
fn durable_vote_retry_and_conflict_survive_witness_sigkill_restart() {
    let directory = value_or_abort(TestDirectory::new("restart"));
    let mut first_witness = value_or_abort(WitnessChild::spawn(&directory));
    let node_a = signed_request("node-a", 19, 3, 1);

    let granted = value_or_abort(request_vote(first_witness.address(), &node_a, IO_TIMEOUT));
    assert_eq!(granted.code(), DecisionCode::GrantedDurablyRecorded);
    assert_eq!(granted.durable_generation(), Some(1));
    let Some(first_proof) = granted.vote() else {
        std::process::abort();
    };
    assert_eq!(first_proof.voter_id().as_str(), "witness");
    assert_eq!(first_proof.key_id().as_str(), TEST_KEY_ID);
    assert!(first_proof.signature_bytes().iter().any(|byte| *byte != 0));

    let retried = value_or_abort(request_vote(first_witness.address(), &node_a, IO_TIMEOUT));
    assert_eq!(retried.code(), DecisionCode::GrantedAlreadyDurable);
    assert_eq!(retried.durable_generation(), Some(1));
    assert_eq!(retried.vote(), granted.vote());

    value_or_abort(first_witness.kill_and_wait());
    let second_witness = value_or_abort(WitnessChild::spawn(&directory));
    let node_b = signed_request("node-b", 19, 9, 2);
    let conflict = value_or_abort(request_vote(second_witness.address(), &node_b, IO_TIMEOUT));
    assert_eq!(conflict.code(), DecisionCode::RefusedConflictSameEpoch);
    assert_eq!(conflict.durable_generation(), None);
    assert!(conflict.vote().is_none());
}

#[test]
fn malformed_oversized_disconnected_and_unauthenticated_peers_never_advance_vote() {
    let directory = value_or_abort(TestDirectory::new("bad-input"));
    let witness = value_or_abort(WitnessChild::spawn(&directory));

    send_oversized_header(witness.address());
    send_framed_and_require_close(witness.address(), b"not-a-vote-request");
    let disconnected = value_or_abort(TcpStream::connect_timeout(&witness.address(), IO_TIMEOUT));
    value_or_abort(disconnected.shutdown(Shutdown::Both));

    let request = signed_request("node-a", 7, 3, 1);
    let mut tampered = value_or_abort(request.to_canonical_bytes());
    let Some(last) = tampered.last_mut() else {
        std::process::abort();
    };
    *last ^= 0x80;
    let auth_response_bytes = value_or_abort(exchange_payload(witness.address(), &tampered));
    let auth_response = value_or_abort(VoteResponse::from_canonical_bytes(&auth_response_bytes));
    assert_eq!(auth_response.code(), DecisionCode::RefusedAuthentication);
    assert!(auth_response.vote().is_none());

    let granted = value_or_abort(request_vote(witness.address(), &request, IO_TIMEOUT));
    assert_eq!(granted.code(), DecisionCode::GrantedDurablyRecorded);
    assert_eq!(granted.durable_generation(), Some(1));
}

#[test]
fn older_epoch_replay_is_refused_after_newer_durable_vote() {
    let directory = value_or_abort(TestDirectory::new("stale"));
    let witness = value_or_abort(WitnessChild::spawn(&directory));
    let current = signed_request("node-a", 10, 10, 10);
    let stale = signed_request("node-a", 9, 9, 9);

    assert_eq!(
        value_or_abort(request_vote(witness.address(), &current, IO_TIMEOUT)).code(),
        DecisionCode::GrantedDurablyRecorded
    );
    let replay = value_or_abort(request_vote(witness.address(), &stale, IO_TIMEOUT));
    assert_eq!(replay.code(), DecisionCode::RefusedStaleEpoch);
    assert!(replay.vote().is_none());
}

#[test]
fn request_codec_is_deterministic_strict_and_authenticated() {
    let request = signed_request("node-a", 5, 5, 5);
    let first = value_or_abort(request.to_canonical_bytes());
    let second = value_or_abort(request.to_canonical_bytes());
    assert_eq!(first, second);
    let decoded = value_or_abort(VoteRequest::from_canonical_bytes(&first));
    assert_eq!(decoded, request);
    assert!(decoded.verify(&TestPeerKeys).is_ok());

    let mut trailing = first.clone();
    trailing.push(0);
    assert!(matches!(
        VoteRequest::from_canonical_bytes(&trailing),
        Err(ProtocolError::TrailingBytes)
    ));

    let mut downgraded = first;
    let Some(version) = downgraded.get_mut(8..10) else {
        std::process::abort();
    };
    version.copy_from_slice(&0_u16.to_be_bytes());
    assert!(matches!(
        VoteRequest::from_canonical_bytes(&downgraded),
        Err(ProtocolError::UnsupportedVersion(0))
    ));
}

fn send_oversized_header(address: SocketAddr) {
    let mut stream = value_or_abort(TcpStream::connect_timeout(&address, IO_TIMEOUT));
    value_or_abort(stream.set_read_timeout(Some(IO_TIMEOUT)));
    let declared = value_or_abort(u32::try_from(MAX_LAB_FRAME_SIZE + 1));
    value_or_abort(stream.write_all(&declared.to_be_bytes()));
    value_or_abort(stream.shutdown(Shutdown::Write));
    require_closed_without_payload(&mut stream);
}

fn send_framed_and_require_close(address: SocketAddr, payload: &[u8]) {
    let mut stream = value_or_abort(TcpStream::connect_timeout(&address, IO_TIMEOUT));
    value_or_abort(stream.set_read_timeout(Some(IO_TIMEOUT)));
    let codec = value_or_abort(FrameCodec::new(MAX_LAB_FRAME_SIZE));
    value_or_abort(codec.write_frame(&mut stream, payload));
    value_or_abort(stream.shutdown(Shutdown::Write));
    require_closed_without_payload(&mut stream);
}

fn require_closed_without_payload(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        Ok(_) | Err(_) => std::process::abort(),
    }
}

fn exchange_payload(address: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut stream = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let codec = FrameCodec::new(MAX_LAB_FRAME_SIZE)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    codec
        .write_frame(&mut stream, payload)
        .map_err(io::Error::other)?;
    codec
        .read_frame(&mut stream)
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "missing response"))
}
