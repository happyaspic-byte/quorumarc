use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_runtime::{
    VoteReasonCode, WitnessOpenReasonCode, WitnessPolicy, WitnessPolicyError, WitnessVoteActor,
};
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
fn key_rotation_preserves_the_durable_proposal_identity() {
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
    let granted = rotated.handle_vote(&request);
    assert_eq!(granted.code(), VoteReasonCode::GrantedAlreadyDurable);
    assert_eq!(granted.durable_generation(), Some(1));
    let Some(vote) = granted.signed_vote() else {
        std::process::abort();
    };
    assert_eq!(vote.key_id().as_str(), "key-2");
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

#[test]
fn witness_policy_rejects_ambiguous_or_self_authorizing_configuration() {
    assert!(matches!(
        WitnessPolicy::new(
            id("witness"),
            id("key-1"),
            id("orders"),
            [0; 32],
            [id("node-a")],
            100,
        ),
        Err(WitnessPolicyError::ZeroPolicyHash)
    ));
    assert!(matches!(
        WitnessPolicy::new(
            id("witness"),
            id("key-1"),
            id("orders"),
            [5; 32],
            Vec::<CanonicalId>::new(),
            100,
        ),
        Err(WitnessPolicyError::NoCandidates)
    ));
    assert!(matches!(
        WitnessPolicy::new(
            id("witness"),
            id("key-1"),
            id("orders"),
            [5; 32],
            [id("witness")],
            100,
        ),
        Err(WitnessPolicyError::WitnessIsCandidate)
    ));
    assert!(matches!(
        WitnessPolicy::new(
            id("witness"),
            id("key-1"),
            id("orders"),
            [5; 32],
            [id("node-a")],
            0,
        ),
        Err(WitnessPolicyError::ZeroLeaseDuration)
    ));
}

#[test]
fn malformed_binding_matrix_never_mutates_or_signs() {
    let directory = value_or_abort(TestDirectory::new("malformed-matrix"));
    let mut actor = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));

    let mut wrong_version = binding("node-a", 2);
    wrong_version.protocol_version = PROTOCOL_VERSION.saturating_add(1);
    let mut zero_message = binding("node-a", 2);
    zero_message.message_id = MessageId::new([0; 16]);
    let mut zero_incarnation = binding("node-a", 2);
    zero_incarnation.candidate_incarnation = 0;
    let zero_epoch = binding("node-a", 0);
    let mut zero_policy = binding("node-a", 2);
    zero_policy.policy_hash = [0; 32];
    let mut zero_root = binding("node-a", 2);
    zero_root.state_root = [0; 32];
    let mut lagging_commit = binding("node-a", 2);
    lagging_commit.durable_commit = lagging_commit.required_commit.saturating_sub(1);
    let mut empty_lease = binding("node-a", 2);
    empty_lease.lease_expires_at_ms = empty_lease.lease_not_before_ms;

    for malformed in [
        wrong_version,
        zero_message,
        zero_incarnation,
        zero_epoch,
        zero_policy,
        zero_root,
        lagging_commit,
        empty_lease,
    ] {
        let reply = actor.handle_vote(&malformed);
        assert_eq!(reply.code(), VoteReasonCode::RefusedMalformedBinding);
        assert!(reply.signed_vote().is_none());
        assert_eq!(reply.durable_generation(), None);
        assert_eq!(actor.durable_generation(), 0);
        assert_eq!(actor.highest_durable_epoch(), 0);
    }
}

#[test]
fn workload_and_candidate_admission_failures_leave_no_durable_trace() {
    let directory = value_or_abort(TestDirectory::new("identity-admission"));
    let mut actor = value_or_abort(WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        directory.path(),
        FileBackend,
    ));

    let mut wrong_workload = binding("node-a", 4);
    wrong_workload.workload_id = id("payments");
    let workload_reply = actor.handle_vote(&wrong_workload);
    assert_eq!(
        workload_reply.code(),
        VoteReasonCode::RefusedWorkloadMismatch
    );
    assert!(workload_reply.signed_vote().is_none());

    let candidate_reply = actor.handle_vote(&binding("node-c", 4));
    assert_eq!(
        candidate_reply.code(),
        VoteReasonCode::RefusedCandidateNotAllowed
    );
    assert!(candidate_reply.signed_vote().is_none());
    assert_eq!(actor.durable_generation(), 0);
    assert_eq!(actor.highest_durable_epoch(), 0);

    let faulted_directory = value_or_abort(TestDirectory::new("open-io"));
    let backend = FaultInjectingBackend::new(
        FileBackend,
        vec![FaultRule {
            operation: FaultOperation::Read,
            occurrence: 1,
            mode: FaultMode::Error(io::ErrorKind::PermissionDenied),
        }],
    );
    let result = WitnessVoteActor::open(
        policy(),
        SigningKey::from_bytes(&WITNESS_KEY),
        faulted_directory.path(),
        backend,
    );
    let Err(error) = result else {
        std::process::abort();
    };
    assert_eq!(error.code(), WitnessOpenReasonCode::StorageIo);
    assert!(error.to_string().contains(error.code().as_str()));
    assert!(error.source().is_some());
}
