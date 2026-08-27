#![allow(clippy::expect_used)]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_rpo0::{
    FileGenericReplica, GenericJournal, GenericJournalError, GenericOperation,
    MemoryGenericReplica, ReplicatedGenericJournal,
};
use sha2::{Digest, Sha256};

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

    let recovered = ReplicatedGenericJournal::recover_from_files(&left_path, &right_path)
        .expect("recover equal files");
    assert_eq!(recovered.progress().commit_index, 2);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn file_generic_replicas_refuse_same_file_and_hard_link_alias() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-alias-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let wal = directory.join("wal.qgwl");
    let alias = directory.join("alias.qgwl");
    fs::write(&wal, b"").expect("create wal");
    fs::hard_link(&wal, &alias).expect("hard link");

    let mut journal = ReplicatedGenericJournal::new();
    let mut left = FileGenericReplica::new("left", &wal);
    let mut right = FileGenericReplica::new("right", &wal);
    assert!(matches!(
        journal.apply(
            GenericOperation::new([12; 16], 0, b"same-path").expect("operation"),
            &mut left,
            &mut right
        ),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));

    let mut journal = ReplicatedGenericJournal::new();
    let mut left = FileGenericReplica::new("left", &wal);
    let mut right = FileGenericReplica::new("right", &alias);
    assert!(matches!(
        journal.apply(
            GenericOperation::new([13; 16], 0, b"hard-link").expect("operation"),
            &mut left,
            &mut right
        ),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&wal, &wal),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&wal, &alias),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn file_generic_replicas_refuse_absent_lexical_alias() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-absent-alias-{}-{sequence}",
        std::process::id()
    ));
    let child = directory.join("child");
    fs::create_dir_all(&child).expect("directory");
    let direct = directory.join("wal.qgwl");
    let lexical_alias = child.join("..").join("wal.qgwl");
    let mut journal = ReplicatedGenericJournal::new();
    let mut left = FileGenericReplica::new("left", &direct);
    let mut right = FileGenericReplica::new("right", &lexical_alias);

    assert!(matches!(
        journal.apply(
            GenericOperation::new([15; 16], 0, b"absent-alias").expect("operation"),
            &mut left,
            &mut right
        ),
        Err(GenericJournalError::ReplicaIdentityCollision)
    ));
    assert!(!direct.exists());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn recovered_generic_journal_exact_retry_does_not_append() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-recover-retry-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let left_path = directory.join("left.qgwl");
    let right_path = directory.join("right.qgwl");
    let mut journal = ReplicatedGenericJournal::new();
    let mut left = FileGenericReplica::new("left", &left_path);
    let mut right = FileGenericReplica::new("right", &right_path);
    let operation = GenericOperation::new([14; 16], 0, b"recover-retry").expect("operation");
    let ack = journal
        .apply(operation.clone(), &mut left, &mut right)
        .expect("dual fsync");
    let left_bytes = fs::read(&left_path).expect("left bytes");
    let right_bytes = fs::read(&right_path).expect("right bytes");

    let mut recovered = ReplicatedGenericJournal::recover_from_files(&left_path, &right_path)
        .expect("recover equal files");
    assert_eq!(recovered.progress().commit_index, 1);
    assert_eq!(recovered.apply(operation, &mut left, &mut right), Ok(ack));
    assert_eq!(fs::read(&left_path).expect("left retry"), left_bytes);
    assert_eq!(fs::read(&right_path).expect("right retry"), right_bytes);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn generic_recovery_refuses_one_copy_divergence_and_corruption() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-recovery-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let left = directory.join("left.qgwl");
    let right = directory.join("right.qgwl");
    fs::write(&left, b"one-copy").expect("one copy");
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&left, &right),
        Err(GenericJournalError::ReplicaUnavailable)
    ));
    fs::write(&right, b"different").expect("different copy");
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&left, &right),
        Err(GenericJournalError::RecoveryMismatch)
    ));
    fs::write(&right, b"one-copy").expect("same corrupt copy");
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&left, &right),
        Err(GenericJournalError::Corrupt)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn generic_journal_exact_retry_refuses_overflow_expected_commit() {
    let mut journal = GenericJournal::new();
    let op = GenericOperation::new([16; 16], 0, b"overflow").expect("op");
    let ack = journal.apply(op).expect("first append");
    assert_eq!(ack.commit_index, 1);

    let overflow_retry = GenericOperation::new([16; 16], u64::MAX, b"overflow").expect("op");
    assert!(matches!(
        journal.apply(overflow_retry),
        Err(GenericJournalError::ConflictingDuplicate)
    ));
}

#[test]
fn generic_recovery_refuses_oversized_file_and_zero_operation_id() {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-generic-oversized-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let left = directory.join("left.qgwl");
    let right = directory.join("right.qgwl");

    let huge = 70_000_000_u64;
    for path in [&left, &right] {
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .expect("create oversized");
        file.set_len(huge).expect("sparse oversized");
    }
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&left, &right),
        Err(GenericJournalError::CapacityExceeded)
    ));

    let zero_id_record = encode_raw_record(1, [0; 16], 0, [0; 32], b"zero-id");
    fs::write(&left, &zero_id_record).expect("write zero left");
    fs::write(&right, &zero_id_record).expect("write zero right");
    assert!(matches!(
        ReplicatedGenericJournal::recover_from_files(&left, &right),
        Err(GenericJournalError::ZeroOperationId)
    ));

    let _ = fs::remove_dir_all(directory);
}

fn encode_raw_record(
    commit_index: u64,
    operation_id: [u8; 16],
    expected_commit: u64,
    previous_root: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"QGWL");
    bytes.push(1);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&commit_index.to_be_bytes());
    bytes.extend_from_slice(&operation_id);
    bytes.extend_from_slice(&expected_commit.to_be_bytes());
    bytes.extend_from_slice(&previous_root);
    bytes.extend_from_slice(payload);
    let mut hasher = Sha256::new();
    hasher.update(b"quorumarc/generic-journal/record/v1\0");
    hasher.update(&bytes);
    let checksum: [u8; 32] = hasher.finalize().into();
    bytes.extend_from_slice(&checksum);
    bytes
}
