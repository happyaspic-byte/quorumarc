use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_runtime::{VoteReasonCode, WitnessOpenReasonCode, WitnessPolicy, WitnessVoteActor};
use quorumarc_store::{FaultInjectingBackend, FaultMode, FaultOperation, FaultRule, FileBackend};
use quorumarc_wire::{CanonicalId, MessageId, PROTOCOL_VERSION, QuorumBinding, SigningKey};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const WITNESS_KEY: [u8; 32] = [29; 32];

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-runtime-{label}-{}-{sequence}",
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

fn value_or_abort<T, E>(result: Result<T, E>) -> T {
    let Ok(value) = result else {
        std::process::abort();
    };
    value
}

fn id(value: &str) -> CanonicalId {
    value_or_abort(CanonicalId::new(value))
}

fn policy() -> WitnessPolicy {
    policy_with_key("key-1")
}

fn policy_with_key(key_id: &str) -> WitnessPolicy {
    value_or_abort(WitnessPolicy::new(
        id("witness"),
        id(key_id),
        id("orders"),
        [5; 32],
        [id("node-a"), id("node-b")],
        100,
    ))
}

fn binding(candidate: &str, epoch: u64) -> QuorumBinding {
    QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new([3; 16]),
        workload_id: id("orders"),
        candidate_node_id: id(candidate),
        candidate_incarnation: 7,
        epoch,
        policy_hash: [5; 32],
        required_commit: 41,
        durable_commit: 41,
        state_root: [7; 32],
        lease_not_before_ms: 10_000,
        lease_expires_at_ms: 10_050,
    }
}

#[test]
fn exact_retry_is_idempotent_across_process_restart() {
    let directory = value_or_abort(TestDirectory::new("retry"));
    let request = binding("node-a", 19);

    let mut first = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    let granted = first.handle_vote(&request);
    assert_eq!(granted.code(), VoteReasonCode::GrantedDurablyRecorded);
    assert_eq!(granted.durable_generation(), Some(1));
    assert!(granted.signed_vote().is_some());
    let first_vote = granted.signed_vote().cloned();
    drop(first);

    let mut recovered = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    assert_eq!(recovered.highest_durable_epoch(), 19);
    let retried = recovered.handle_vote(&request);
    assert_eq!(retried.code(), VoteReasonCode::GrantedAlreadyDurable);
    assert_eq!(retried.durable_generation(), Some(1));
    assert_eq!(retried.signed_vote(), first_vote.as_ref());
}

#[test]
fn conflicting_candidate_is_refused_after_restart_without_signature() {
    let directory = value_or_abort(TestDirectory::new("candidate-conflict"));
    let mut first = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    assert!(first.handle_vote(&binding("node-a", 7)).is_granted());
    drop(first);

    let mut recovered = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    let refused = recovered.handle_vote(&binding("node-b", 7));
    assert_eq!(refused.code(), VoteReasonCode::RefusedConflictSameEpoch);
    assert!(refused.signed_vote().is_none());
    assert_eq!(recovered.durable_generation(), 1);
}

#[test]
fn conflicting_binding_digest_is_refused_after_restart() {
    let directory = value_or_abort(TestDirectory::new("digest-conflict"));
    let request = binding("node-a", 9);
    let mut first = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    assert!(first.handle_vote(&request).is_granted());
    drop(first);

    let mut changed = request;
    changed.message_id = MessageId::new([44; 16]);
    changed.state_root = [55; 32];
    let mut recovered = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    let refused = recovered.handle_vote(&changed);
    assert_eq!(refused.code(), VoteReasonCode::RefusedConflictSameEpoch);
    assert!(!refused.is_granted());
}

#[test]
fn key_rotation_cannot_resign_an_already_voted_epoch() {
    let directory = value_or_abort(TestDirectory::new("key-rotation"));
    let request = binding("node-a", 10);
    let mut first = value_or_abort(WitnessVoteActor::open(
        policy_with_key("key-1"),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    assert!(first.handle_vote(&request).is_granted());
    drop(first);

    let mut rotated = value_or_abort(WitnessVoteActor::open(
        policy_with_key("key-2"),
        SigningKey::from_bytes(&[31; 32]),
        directory.path(),
        FileBackend,
    ));
    let refused = rotated.handle_vote(&request);
    assert_eq!(refused.code(), VoteReasonCode::RefusedConflictSameEpoch);
    assert!(refused.signed_vote().is_none());
}

#[test]
fn durability_failure_never_releases_a_signature_and_poisons_actor() {
    let directory = value_or_abort(TestDirectory::new("durability-failure"));
    let backend = FaultInjectingBackend::new(
        FileBackend,
        vec![FaultRule {
            operation: FaultOperation::Write,
            occurrence: 1,
            mode: FaultMode::PartialWrite {
                bytes: 11,
                error_kind: io::ErrorKind::WriteZero,
            },
        }],
    );
    let mut actor = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        backend,
    ));

    let failed = actor.handle_vote(&binding("node-a", 3));
    assert_eq!(failed.code(), VoteReasonCode::RefusedDurabilityIo);
    assert!(failed.signed_vote().is_none());
    assert!(actor.is_store_poisoned());

    let retry = actor.handle_vote(&binding("node-a", 3));
    assert_eq!(retry.code(), VoteReasonCode::RefusedStorePoisoned);
    assert!(retry.signed_vote().is_none());
}

#[test]
fn malformed_or_policy_mismatched_binding_does_not_advance_store() {
    let directory = value_or_abort(TestDirectory::new("admission"));
    let mut actor = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));

    let mut malformed = binding("node-a", 2);
    malformed.durable_commit = malformed.required_commit.saturating_sub(1);
    assert_eq!(
        actor.handle_vote(&malformed).code(),
        VoteReasonCode::RefusedMalformedBinding
    );

    let mut wrong_policy = binding("node-a", 2);
    wrong_policy.policy_hash = [99; 32];
    assert_eq!(
        actor.handle_vote(&wrong_policy).code(),
        VoteReasonCode::RefusedPolicyMismatch
    );

    let mut long_lease = binding("node-a", 2);
    long_lease.lease_expires_at_ms = long_lease.lease_not_before_ms + 101;
    assert_eq!(
        actor.handle_vote(&long_lease).code(),
        VoteReasonCode::RefusedLeaseTooLong
    );
    assert_eq!(actor.highest_durable_epoch(), 0);
    assert_eq!(actor.durable_generation(), 0);
}

#[test]
fn stale_epoch_is_refused_after_a_newer_durable_vote() {
    let directory = value_or_abort(TestDirectory::new("stale"));
    let mut actor = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));
    assert!(actor.handle_vote(&binding("node-a", 12)).is_granted());
    let stale = actor.handle_vote(&binding("node-a", 11));
    assert_eq!(stale.code(), VoteReasonCode::RefusedStaleEpoch);
    assert!(stale.signed_vote().is_none());
}

#[test]
fn corrupt_committed_state_refuses_actor_recovery() {
    let directory = value_or_abort(TestDirectory::new("corrupt"));
    value_or_abort(fs::write(
        directory.path().join("authority.journal"),
        b"truncated",
    ));
    let result = WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    );
    let Err(error) = result else {
        std::process::abort();
    };
    assert_eq!(error.code(), WitnessOpenReasonCode::CorruptAuthorityState);
}

#[test]
fn reason_codes_have_stable_distinct_spellings() {
    let codes = [
        VoteReasonCode::GrantedDurablyRecorded,
        VoteReasonCode::GrantedAlreadyDurable,
        VoteReasonCode::RefusedMalformedBinding,
        VoteReasonCode::RefusedWorkloadMismatch,
        VoteReasonCode::RefusedPolicyMismatch,
        VoteReasonCode::RefusedCandidateNotAllowed,
        VoteReasonCode::RefusedLeaseTooLong,
        VoteReasonCode::RefusedStaleEpoch,
        VoteReasonCode::RefusedConflictSameEpoch,
        VoteReasonCode::RefusedEpochAlreadyAccepted,
        VoteReasonCode::RefusedStorePoisoned,
        VoteReasonCode::RefusedDurabilityIo,
        VoteReasonCode::RefusedStoreInvariant,
        VoteReasonCode::RefusedGenerationExhausted,
        VoteReasonCode::RefusedSigningFailure,
    ];
    for (index, code) in codes.iter().enumerate() {
        assert!(code.as_str().starts_with("VOTE_"));
        assert!(
            codes[index + 1..]
                .iter()
                .all(|other| other.as_str() != code.as_str())
        );
    }
}
