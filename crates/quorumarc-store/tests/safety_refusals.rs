use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_store::{
    ActivationReceipt, DurableAuthorityStore, FaultInjectingBackend, FaultMode, FaultOperation,
    FaultRule, FileBackend, LeaseBounds, ModelError, PromotionRecord, StateRoot, StoreError,
    TransitionOutcome, VoteRecord,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-store-refusal-{label}-{}-{sequence}",
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

fn vote(epoch: u64, candidate: &str, proposal: [u8; 32]) -> Result<VoteRecord, ModelError> {
    VoteRecord::new(epoch, candidate, proposal)
}

fn promotion(
    epoch: u64,
    proposal: [u8; 32],
    final_digest: [u8; 32],
) -> Result<PromotionRecord, ModelError> {
    PromotionRecord::new(
        epoch,
        proposal,
        final_digest,
        LeaseBounds::new(100, 1_000)?,
        41,
        StateRoot::new([9; 32]),
    )
}

#[test]
fn model_constructors_reject_authority_sentinels_and_noncanonical_ids() {
    assert!(matches!(
        VoteRecord::new(0, "node-a", [1; 32]),
        Err(ModelError::ZeroEpoch)
    ));
    assert!(matches!(
        VoteRecord::new(1, "", [1; 32]),
        Err(ModelError::EmptyIdentifier)
    ));
    assert!(matches!(
        VoteRecord::new(1, "node/a", [1; 32]),
        Err(ModelError::InvalidIdentifierCharacter)
    ));
    assert!(matches!(
        VoteRecord::new(1, "x".repeat(129), [1; 32]),
        Err(ModelError::IdentifierTooLong)
    ));
    assert!(matches!(
        LeaseBounds::new(10, 10),
        Err(ModelError::InvalidLease)
    ));
    assert!(matches!(
        LeaseBounds::new(11, 10),
        Err(ModelError::InvalidLease)
    ));
    assert!(matches!(
        ActivationReceipt::new(0, "node-a", 1, [2; 32], 100, 200),
        Err(ModelError::ZeroEpoch)
    ));
    assert!(matches!(
        ActivationReceipt::new(1, "node-a", 0, [2; 32], 100, 200),
        Err(ModelError::ZeroIncarnation)
    ));
    assert!(matches!(
        ActivationReceipt::new(1, "node-a", 1, [2; 32], 200, 200),
        Err(ModelError::InvalidActivationTime)
    ));
}

#[test]
fn promotion_requires_the_exact_durable_proposal_and_is_idempotent() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("promotion")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;

    let missing_vote = store.record_promotion(promotion(7, [1; 32], [2; 32])?);
    assert!(matches!(
        missing_vote,
        Err(StoreError::MissingVote { epoch: 7 })
    ));
    assert_eq!(store.generation(), 0);

    store.record_vote(vote(7, "node-a", [1; 32])?)?;
    let generation_after_vote = store.generation();
    let wrong_proposal = store.record_promotion(promotion(7, [3; 32], [2; 32])?);
    assert!(matches!(
        wrong_proposal,
        Err(StoreError::VoteDigestMismatch { epoch: 7 })
    ));
    assert_eq!(store.generation(), generation_after_vote);

    let accepted = promotion(7, [1; 32], [2; 32])?;
    let committed = store.record_promotion(accepted.clone())?;
    assert_eq!(committed.outcome(), TransitionOutcome::Committed);
    let retry = store.record_promotion(accepted)?;
    assert_eq!(retry.outcome(), TransitionOutcome::AlreadyDurable);
    assert_eq!(retry.generation(), committed.generation());

    let conflict = store.record_promotion(promotion(7, [1; 32], [4; 32])?);
    assert!(matches!(
        conflict,
        Err(StoreError::ConflictingPromotion { epoch: 7 })
    ));
    assert_eq!(store.generation(), committed.generation());
    Ok(())
}

#[test]
fn activation_must_match_holder_incarnation_final_digest_and_lease() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("activation")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    store.allocate_incarnation(7)?;
    store.record_vote(vote(9, "node-a", [1; 32])?)?;
    store.record_promotion(promotion(9, [1; 32], [2; 32])?)?;
    let generation = store.generation();

    let mismatches = [
        ActivationReceipt::new(9, "node-b", 7, [2; 32], 100, 1_000)?,
        ActivationReceipt::new(9, "node-a", 8, [2; 32], 100, 1_000)?,
        ActivationReceipt::new(9, "node-a", 7, [3; 32], 100, 1_000)?,
        ActivationReceipt::new(9, "node-a", 7, [2; 32], 99, 1_000)?,
        ActivationReceipt::new(9, "node-a", 7, [2; 32], 100, 999)?,
    ];
    for receipt in mismatches {
        assert!(matches!(
            store.record_activation(receipt),
            Err(StoreError::ActivationMismatch)
        ));
        assert_eq!(store.generation(), generation);
        assert!(store.state().activation_receipt().is_none());
    }

    let valid = ActivationReceipt::new(9, "node-a", 7, [2; 32], 100, 1_000)?;
    let committed = store.record_activation(valid.clone())?;
    assert_eq!(committed.outcome(), TransitionOutcome::Committed);
    let retry = store.record_activation(valid)?;
    assert_eq!(retry.outcome(), TransitionOutcome::AlreadyDurable);
    assert_eq!(retry.generation(), committed.generation());

    let conflict = ActivationReceipt::new(9, "node-a", 7, [2; 32], 101, 1_000)?;
    assert!(matches!(
        store.record_activation(conflict),
        Err(StoreError::ConflictingActivation { epoch: 9 })
    ));
    Ok(())
}

#[test]
fn recovery_io_failures_for_create_read_and_cleanup_are_typed() -> Result<(), Box<dyn Error>> {
    for (label, operation) in [
        ("create", FaultOperation::CreateDirectory),
        ("read", FaultOperation::Read),
        ("cleanup", FaultOperation::Remove),
    ] {
        let directory = TestDirectory::new(label)?;
        let target = directory.path().join("store");
        if operation != FaultOperation::CreateDirectory {
            fs::create_dir_all(&target)?;
        }
        let backend = FaultInjectingBackend::new(
            FileBackend,
            vec![FaultRule {
                operation,
                occurrence: 1,
                mode: FaultMode::Error(io::ErrorKind::PermissionDenied),
            }],
        );
        let result = DurableAuthorityStore::open_in(&target, backend);
        let Err(StoreError::Io {
            kind: io::ErrorKind::PermissionDenied,
            ..
        }) = result
        else {
            std::process::abort();
        };
    }
    Ok(())
}
