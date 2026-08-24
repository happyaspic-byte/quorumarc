use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_store::{
    ActivationReceipt, Corruption, DurableAuthorityStore, FaultInjectingBackend, FaultMode,
    FaultOperation, FaultRule, FileBackend, LeaseBounds, PromotionRecord, StateRoot, StoreError,
    StorePaths, TransitionOutcome, VoteRecord,
};

static TEST_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(1);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create(label: &str) -> io::Result<Self> {
        let counter = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-store-{label}-{}-{counter}",
            std::process::id()
        ));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.path);
    }
}

fn sample_vote(
    epoch: u64,
    candidate: &str,
    digest: [u8; 32],
) -> Result<VoteRecord, Box<dyn Error>> {
    Ok(VoteRecord::new(epoch, candidate, digest)?)
}

fn sample_promotion(
    epoch: u64,
    proposal_digest: [u8; 32],
    signed_envelope_digest: [u8; 32],
) -> Result<PromotionRecord, Box<dyn Error>> {
    Ok(PromotionRecord::new(
        epoch,
        proposal_digest,
        signed_envelope_digest,
        LeaseBounds::new(100, 1_000)?,
        41,
        StateRoot::new([9; 32]),
    )?)
}

#[test]
fn restart_recovers_complete_authority_state() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("restart")?;
    let proposal_digest = [7; 32];
    let signed_envelope_digest = [8; 32];
    let generation = {
        let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
        store.allocate_incarnation(12)?;
        store.record_vote(sample_vote(5, "node-a", proposal_digest)?)?;
        store.record_promotion(sample_promotion(
            5,
            proposal_digest,
            signed_envelope_digest,
        )?)?;
        let activation = ActivationReceipt::new(
            5,
            "node-a",
            12,
            signed_envelope_digest,
            120,
            1_000,
        )?;
        let receipt = store.record_activation(activation)?;
        assert_eq!(receipt.outcome(), TransitionOutcome::Committed);
        receipt.generation()
    };

    let recovered = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    assert_eq!(recovered.generation(), generation);
    assert_eq!(recovered.state().highest_epoch(), 5);
    assert_eq!(recovered.state().incarnation(), 12);
    assert_eq!(recovered.state().commit_index(), 41);
    assert_eq!(
        recovered.state().state_root(),
        Some(StateRoot::new([9; 32]))
    );
    assert_eq!(
        recovered.state().last_vote().map(VoteRecord::candidate),
        Some("node-a")
    );
    assert_eq!(
        recovered
            .state()
            .last_promotion()
            .map(PromotionRecord::proposal_digest),
        Some(&proposal_digest)
    );
    assert_eq!(
        recovered
            .state()
            .last_promotion()
            .map(PromotionRecord::signed_envelope_digest),
        Some(&signed_envelope_digest)
    );
    assert_eq!(
        recovered
            .state()
            .activation_receipt()
            .map(ActivationReceipt::holder),
        Some("node-a")
    );
    Ok(())
}

#[test]
fn exact_vote_retry_is_idempotent_but_double_vote_is_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("double-vote")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    let vote = sample_vote(8, "node-a", [1; 32])?;
    let first = store.record_vote(vote.clone())?;
    let retry = store.record_vote(vote)?;
    assert_eq!(retry.outcome(), TransitionOutcome::AlreadyDurable);
    assert_eq!(retry.generation(), first.generation());

    let error = store
        .record_vote(sample_vote(8, "node-b", [2; 32])?)
        .err()
        .ok_or("double vote unexpectedly succeeded")?;
    assert!(matches!(error, StoreError::DoubleVote { epoch: 8 }));
    assert_eq!(
        store.state().last_vote().map(VoteRecord::candidate),
        Some("node-a")
    );
    Ok(())
}

#[test]
fn stale_epoch_is_rejected_without_a_write() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("stale-epoch")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    store.record_vote(sample_vote(11, "node-a", [1; 32])?)?;
    let generation = store.generation();
    let error = store
        .record_vote(sample_vote(10, "node-a", [2; 32])?)
        .err()
        .ok_or("stale vote unexpectedly succeeded")?;
    assert!(matches!(
        error,
        StoreError::StaleEpoch {
            requested: 10,
            durable: 11
        }
    ));
    assert_eq!(store.generation(), generation);
    Ok(())
}

#[test]
fn truncated_committed_frame_fails_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("truncated")?;
    let paths = StorePaths::new(directory.path());
    {
        let mut store = DurableAuthorityStore::open(paths.clone(), FileBackend)?;
        store.allocate_incarnation(1)?;
    }
    let mut bytes = fs::read(paths.committed())?;
    bytes.truncate(bytes.len() / 2);
    fs::write(paths.committed(), bytes)?;
    let error = DurableAuthorityStore::open(paths, FileBackend)
        .err()
        .ok_or("truncated frame unexpectedly recovered")?;
    assert!(matches!(error, StoreError::Corrupt(_)));
    Ok(())
}

#[test]
fn checksum_corruption_fails_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("corrupt")?;
    let paths = StorePaths::new(directory.path());
    {
        let mut store = DurableAuthorityStore::open(paths.clone(), FileBackend)?;
        store.allocate_incarnation(2)?;
    }
    let mut bytes = fs::read(paths.committed())?;
    let offset = 30;
    let byte = bytes
        .get_mut(offset)
        .ok_or("test frame was unexpectedly short")?;
    *byte ^= 0x5a;
    fs::write(paths.committed(), bytes)?;
    let error = DurableAuthorityStore::open(paths, FileBackend)
        .err()
        .ok_or("corrupt frame unexpectedly recovered")?;
    assert!(matches!(error, StoreError::Corrupt(_)));
    Ok(())
}

#[test]
fn partial_write_cannot_replace_previous_durable_state() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("partial-write")?;
    {
        let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
        store.allocate_incarnation(3)?;
    }
    let fault = FaultRule {
        operation: FaultOperation::Write,
        occurrence: 1,
        mode: FaultMode::PartialWrite {
            bytes: 17,
            error_kind: io::ErrorKind::WriteZero,
        },
    };
    {
        let backend = FaultInjectingBackend::new(FileBackend, vec![fault]);
        let mut store = DurableAuthorityStore::open_in(directory.path(), backend)?;
        let error = store
            .allocate_incarnation(4)
            .err()
            .ok_or("partial write unexpectedly committed")?;
        assert!(matches!(error, StoreError::Io { .. }));
        assert!(store.is_poisoned());
        assert_eq!(store.state().incarnation(), 3);
    }
    let recovered = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    assert_eq!(recovered.state().incarnation(), 3);
    Ok(())
}

#[test]
fn write_sync_and_rename_failures_never_acknowledge() -> Result<(), Box<dyn Error>> {
    for (label, operation) in [
        ("write-failure", FaultOperation::Write),
        ("sync-failure", FaultOperation::SyncFile),
        ("rename-failure", FaultOperation::Rename),
    ] {
        let directory = TestDirectory::create(label)?;
        let fault = FaultRule {
            operation,
            occurrence: 1,
            mode: FaultMode::Error(io::ErrorKind::Other),
        };
        let backend = FaultInjectingBackend::new(FileBackend, vec![fault]);
        let mut store = DurableAuthorityStore::open_in(directory.path(), backend)?;
        let error = store
            .allocate_incarnation(1)
            .err()
            .ok_or("faulted transition unexpectedly succeeded")?;
        assert!(matches!(error, StoreError::Io { .. }));
        assert!(store.is_poisoned());
        assert_eq!(store.generation(), 0);
        drop(store);

        let recovered = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
        assert_eq!(recovered.generation(), 0);
        assert_eq!(recovered.state().incarnation(), 0);
    }
    Ok(())
}

#[test]
fn directory_sync_failure_is_unknown_and_requires_recovery() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("directory-sync")?;
    let fault = FaultRule {
        operation: FaultOperation::SyncDirectory,
        occurrence: 1,
        mode: FaultMode::Error(io::ErrorKind::Other),
    };
    let backend = FaultInjectingBackend::new(FileBackend, vec![fault]);
    let mut store = DurableAuthorityStore::open_in(directory.path(), backend)?;
    let error = store
        .allocate_incarnation(9)
        .err()
        .ok_or("directory sync failure unexpectedly acknowledged")?;
    assert!(matches!(error, StoreError::Io { .. }));
    assert!(store.is_poisoned());
    assert_eq!(store.generation(), 0);
    drop(store);

    // Rename completed before the directory-sync failure. Recovery reads the
    // visible complete frame and still never revives less authority than disk.
    let recovered = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    assert_eq!(recovered.state().incarnation(), 9);
    assert_eq!(recovered.generation(), 1);
    Ok(())
}

#[test]
fn promotion_requires_matching_durable_vote() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("vote-binding")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    store.allocate_incarnation(1)?;
    store.record_vote(sample_vote(2, "node-a", [1; 32])?)?;
    let error = store
        .record_promotion(sample_promotion(2, [2; 32], [3; 32])?)
        .err()
        .ok_or("mismatched promotion unexpectedly succeeded")?;
    assert!(matches!(error, StoreError::VoteDigestMismatch { epoch: 2 }));
    assert!(store.state().last_promotion().is_none());
    Ok(())
}

#[test]
fn activation_requires_final_signed_envelope_digest() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("activation-final-digest")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    let proposal_digest = [4; 32];
    let signed_envelope_digest = [5; 32];
    store.allocate_incarnation(9)?;
    store.record_vote(sample_vote(12, "node-a", proposal_digest)?)?;
    store.record_promotion(sample_promotion(
        12,
        proposal_digest,
        signed_envelope_digest,
    )?)?;

    let mismatched = ActivationReceipt::new(12, "node-a", 9, proposal_digest, 120, 1_000)?;
    let error = store
        .record_activation(mismatched)
        .err()
        .ok_or("proposal digest unexpectedly activated as a final envelope")?;
    assert!(matches!(error, StoreError::ActivationMismatch));
    assert!(store.state().activation_receipt().is_none());
    Ok(())
}

#[test]
fn old_and_unknown_journal_versions_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("unsupported-version")?;
    let paths = StorePaths::new(directory.path());
    {
        let mut store = DurableAuthorityStore::open(paths.clone(), FileBackend)?;
        store.allocate_incarnation(1)?;
    }
    let current = fs::read(paths.committed())?;
    for version in [1_u16, 3_u16, u16::MAX] {
        let mut changed = current.clone();
        let version_bytes = changed
            .get_mut(8..10)
            .ok_or("journal frame was unexpectedly shorter than its header")?;
        version_bytes.copy_from_slice(&version.to_le_bytes());
        fs::write(paths.committed(), changed)?;
        let error = DurableAuthorityStore::open(paths.clone(), FileBackend)
            .err()
            .ok_or("unsupported journal version unexpectedly recovered")?;
        assert!(matches!(
            error,
            StoreError::Corrupt(Corruption::UnsupportedVersion)
        ));
    }
    Ok(())
}

#[test]
fn progress_cannot_regress_or_change_root_at_same_index() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::create("progress")?;
    let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
    store.record_progress(20, StateRoot::new([1; 32]))?;
    let regression = store
        .record_progress(19, StateRoot::new([1; 32]))
        .err()
        .ok_or("commit regression unexpectedly succeeded")?;
    assert!(matches!(regression, StoreError::CommitRegression { .. }));
    let conflict = store
        .record_progress(20, StateRoot::new([2; 32]))
        .err()
        .ok_or("state root conflict unexpectedly succeeded")?;
    assert!(matches!(conflict, StoreError::StateRootConflict { .. }));
    Ok(())
}
