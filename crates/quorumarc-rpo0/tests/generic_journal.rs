#![allow(clippy::expect_used)]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_rpo0::{
    FileGenericReplica, GenericJournal, GenericJournalError, GenericOperation,
    MemoryGenericReplica, ReplicatedGenericJournal,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

#[test]
fn generic_journal_chains_payloads_and_confirms_exact_retry() {
    let mut journal = GenericJournal::new();
    let first = GenericOperation::new([1; 16], 0, b"first-record").expect("first operation");
    let first_ack = journal.apply(first.clone()).expect("first append");
    assert_eq!(first_ack.commit_index, 1);
    assert_eq!(journal.apply(first), Ok(first_ack));
    assert_eq!(journal.len(), 1);

    let second = GenericOperation::new([2; 16], 1, b"second-record").expect("second operation");
    let second_ack = journal.apply(second).expect("second append");
    assert_eq!(second_ack.commit_index, 2);
    assert_ne!(second_ack.state_root, first_ack.state_root);
    assert_eq!(journal.recover().expect("recover").commit_index, 2);
}

#[test]
fn generic_journal_refuses_conflicting_ids_stale_commits_and_corruption() {
    let mut journal = GenericJournal::new();
    journal
        .apply(GenericOperation::new([3; 16], 0, b"payload-a").expect("operation"))
        .expect("append");
    assert!(matches!(
        journal.apply(GenericOperation::new([3; 16], 0, b"payload-b").expect("conflict")),
        Err(GenericJournalError::ConflictingDuplicate)
    ));
    assert!(matches!(
        journal.apply(GenericOperation::new([4; 16], 0, b"stale").expect("stale")),
        Err(GenericJournalError::StaleCommit)
    ));
    journal.corrupt_byte(8);
    assert!(matches!(
        journal.recover(),
        Err(GenericJournalError::Corrupt)
    ));
}

#[test]
fn generic_journal_bounds_payload_size() {
    assert!(matches!(
        GenericOperation::new([5; 16], 0, &vec![0; 65_537]),
        Err(GenericJournalError::PayloadTooLarge)
    ));
}

#[test]
fn replicated_generic_journal_requires_two_distinct_durable_receipts() {
    let mut journal = ReplicatedGenericJournal::new();
    let mut left = MemoryGenericReplica::new("left");
    let mut right = MemoryGenericReplica::new("right");
    let first = GenericOperation::new([7; 16], 0, b"payload-one").expect("operation");
    let ack = journal
        .apply(first.clone(), &mut left, &mut right)
        .expect("dual durable");
    assert_eq!(ack.commit_index, 1);
    assert_eq!(left.append_count(), 1);
    assert_eq!(right.append_count(), 1);
    assert_eq!(journal.apply(first, &mut left, &mut right), Ok(ack));
    assert_eq!(left.append_count(), 1);
    assert_eq!(right.append_count(), 1);
}

#[test]
fn replicated_generic_journal_refuses_one_copy_and_identical_replica_ids() {
    let mut journal = ReplicatedGenericJournal::new();
    let mut left = MemoryGenericReplica::new("same");
    let mut colliding = MemoryGenericReplica::new("same");
    assert!(matches!(
        journal.apply(
            GenericOperation::new([8; 16], 0, b"payload").expect("operation"),
            &mut left,
            &mut colliding
        ),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));

    let mut right = MemoryGenericReplica::new("right");
    right.fail_next();
    assert!(matches!(
        journal.apply(
            GenericOperation::new([9; 16], 0, b"payload").expect("operation"),
            &mut left,
            &mut right
        ),
        Err(GenericJournalError::ReplicaUnavailable)
    ));
    assert!(journal.is_uncertain());
    assert!(matches!(
        journal.apply(
            GenericOperation::new([9; 16], 0, b"payload").expect("retry"),
            &mut left,
            &mut right
        ),
        Err(GenericJournalError::UncertainDurability)
    ));
}

#[test]
fn file_generic_replicas_fsync_equal_wals_and_exact_retry_does_not_append() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-file-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let left_path = directory.join("left.qgwl");
    let right_path = directory.join("right.qgwl");
    let mut journal = ReplicatedGenericJournal::new();
    let mut left = FileGenericReplica::new("left", &left_path);
    let mut right = FileGenericReplica::new("right", &right_path);
    let operation = GenericOperation::new([10; 16], 0, b"file-payload").expect("operation");
    let ack = journal
        .apply(operation.clone(), &mut left, &mut right)
        .expect("dual fsync");
    let left_bytes = fs::read(&left_path).expect("left bytes");
    let right_bytes = fs::read(&right_path).expect("right bytes");
    assert_eq!(left_bytes, right_bytes);
    assert!(!left_bytes.is_empty());
    assert_eq!(journal.apply(operation, &mut left, &mut right), Ok(ack));
    assert_eq!(fs::read(&left_path).expect("left retry"), left_bytes);
    assert_eq!(fs::read(&right_path).expect("right retry"), right_bytes);

    let second = GenericOperation::new([11; 16], 1, b"second-file-payload").expect("second");
    let second_ack = journal
        .apply(second, &mut left, &mut right)
        .expect("second dual fsync");
    assert_eq!(second_ack.commit_index, 2);
    assert_eq!(
        fs::read(&left_path).expect("left second"),
        fs::read(&right_path).expect("right second")
    );
    assert!(fs::metadata(&left_path).expect("left metadata").len() > left_bytes.len() as u64);
    let _ = fs::remove_dir_all(directory);
}
