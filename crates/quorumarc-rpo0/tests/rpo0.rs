#![allow(clippy::expect_used)]

use quorumarc_rpo0::{
    recover_wal, CounterOperation, Fault, MemoryReplica, OperationId, ReplicatedCounter,
    Rpo0Error, WalCorruption,
};

fn operation(id: u8, expected_commit_index: u64, increment: u64) -> CounterOperation {
    CounterOperation {
        id: OperationId::new([id; 16]),
        expected_commit_index,
        increment,
    }
}

#[test]
fn exact_duplicate_returns_stable_ack_without_second_append() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    let first = counter
        .apply(operation(1, 0, 5), &mut left, &mut right)
        .expect("first write should be acknowledged");
    let duplicate = counter
        .apply(operation(1, 0, 5), &mut left, &mut right)
        .expect("exact duplicate should return the stable acknowledgement");
    assert_eq!(first, duplicate);
    assert_eq!(left.append_count(), 1);
    assert_eq!(right.append_count(), 1);
}

#[test]
fn reused_operation_id_with_different_content_is_rejected() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(2, 0, 1), &mut left, &mut right)
        .expect("first write should be acknowledged");
    let error = counter
        .apply(operation(2, 1, 2), &mut left, &mut right)
        .expect_err("changed duplicate must fail");
    assert!(matches!(error, Rpo0Error::ConflictingDuplicate(_)));
}

#[test]
fn one_replica_failure_refuses_ack_and_poisoned_writer_stays_closed() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    right.inject_once(Fault::FailBeforeAppend);
    let error = counter
        .apply(operation(3, 0, 1), &mut left, &mut right)
        .expect_err("single durable replica is insufficient");
    assert!(matches!(
        error,
        Rpo0Error::ReplicaUnavailable {
            replica: "right",
            ..
        }
    ));
    assert_eq!(counter.commit_index(), 0);
    assert_eq!(counter.value(), 0);
    assert!(counter.is_uncertain());
    assert!(matches!(
        counter.apply(operation(4, 0, 1), &mut left, &mut right),
        Err(Rpo0Error::UncertainDurability)
    ));
}

#[test]
fn missing_replica_refuses_ack_before_any_append() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let error = counter
        .apply_available(operation(19, 0, 1), Some(&mut left), None)
        .expect_err("a missing replica cannot satisfy RPO-0");
    assert!(matches!(error, Rpo0Error::ReplicaMissing("right")));
    assert_eq!(left.append_count(), 0);
    assert!(!counter.is_uncertain());
}

#[test]
fn acknowledged_write_is_recoverable_from_either_replica() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    let acknowledgement = counter
        .apply(operation(5, 0, 7), &mut left, &mut right)
        .expect("both durable replicas should permit acknowledgement");
    let left_recovery = recover_wal(left.bytes()).expect("left WAL should recover");
    let right_recovery = recover_wal(right.bytes()).expect("right WAL should recover");
    assert_eq!(left_recovery, right_recovery);
    assert_eq!(left_recovery.commit_index, acknowledgement.commit_index);
    assert_eq!(left_recovery.value, acknowledgement.value);
    assert_eq!(left_recovery.state_root, acknowledgement.state_root);
}

#[test]
fn truncated_wal_fails_closed() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(6, 0, 1), &mut left, &mut right)
        .expect("write should be acknowledged");
    let truncated = &left.bytes()[..left.bytes().len() - 1];
    assert_eq!(recover_wal(truncated), Err(WalCorruption::Truncated));
}

#[test]
fn corrupt_wal_fails_closed() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(7, 0, 1), &mut left, &mut right)
        .expect("write should be acknowledged");
    assert!(left.corrupt_byte(20));
    assert_eq!(
        recover_wal(left.bytes()),
        Err(WalCorruption::ChecksumMismatch)
    );
}

#[test]
fn stale_and_future_operations_are_rejected_before_replica_io() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(8, 0, 1), &mut left, &mut right)
        .expect("initial operation should be acknowledged");
    assert!(matches!(
        counter.apply(operation(9, 0, 1), &mut left, &mut right),
        Err(Rpo0Error::StaleOperation {
            expected: 0,
            actual: 1
        })
    ));
    assert!(matches!(
        counter.apply(operation(10, 2, 1), &mut left, &mut right),
        Err(Rpo0Error::OutOfOrderOperation {
            expected: 2,
            actual: 1
        })
    ));
    assert_eq!(left.append_count(), 1);
    assert_eq!(right.append_count(), 1);
}

#[test]
fn identical_replica_identity_cannot_satisfy_rpo0() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("same");
    let mut right = MemoryReplica::new("same");
    assert!(matches!(
        counter.apply(operation(11, 0, 1), &mut left, &mut right),
        Err(Rpo0Error::ReplicaIdentityCollision)
    ));
}

#[test]
fn invalid_receipt_refuses_ack() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    right.inject_once(Fault::InvalidReceipt);
    assert!(matches!(
        counter.apply(operation(12, 0, 1), &mut left, &mut right),
        Err(Rpo0Error::InvalidDurabilityReceipt("right"))
    ));
    assert!(counter.is_uncertain());
}

#[test]
fn recovered_replica_mismatch_is_rejected() {
    let mut first = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    first
        .apply(operation(13, 0, 1), &mut left, &mut right)
        .expect("write should be acknowledged");
    let populated = recover_wal(left.bytes()).expect("WAL should recover");
    let empty = recover_wal(&[]).expect("empty WAL should recover");
    assert!(matches!(
        ReplicatedCounter::from_recovered(populated, empty),
        Err(Rpo0Error::RecoveryMismatch)
    ));
}

#[test]
fn multiple_entries_recover_with_deterministic_promotion_progress() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(14, 0, 2), &mut left, &mut right)
        .expect("first operation should be acknowledged");
    let second = counter
        .apply(operation(15, 1, 3), &mut left, &mut right)
        .expect("second operation should be acknowledged");
    assert_eq!(left.bytes(), right.bytes());
    let recovered = recover_wal(left.bytes()).expect("canonical WAL should recover");
    assert_eq!(recovered.commit_index, 2);
    assert_eq!(recovered.value, 5);
    assert_eq!(recovered.state_root, second.state_root);
    assert_eq!(
        counter.promotion_progress().durable_commit_index,
        recovered.commit_index
    );
    assert_eq!(
        counter.promotion_progress().state_root,
        recovered.state_root
    );
}

#[test]
fn recovery_preserves_dedupe_without_reapplying_an_old_operation() {
    let mut original = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    original
        .apply(operation(16, 0, 4), &mut left, &mut right)
        .expect("operation should be acknowledged");
    let recovered = recover_wal(left.bytes()).expect("WAL should recover");
    let mut restarted = ReplicatedCounter::from_recovered(recovered.clone(), recovered)
        .expect("matching replicas should recover");
    let mut new_left = MemoryReplica::new("new-left");
    let mut new_right = MemoryReplica::new("new-right");
    let duplicate = restarted
        .apply(operation(16, 0, 4), &mut new_left, &mut new_right)
        .expect("known operation should return its recovered result");
    assert_eq!(duplicate.commit_index, 1);
    assert_eq!(duplicate.value, 4);
    assert_eq!(new_left.append_count(), 0);
    assert_eq!(new_right.append_count(), 0);
}

#[test]
fn preexisting_replica_corruption_blocks_the_next_write() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    counter
        .apply(operation(17, 0, 1), &mut left, &mut right)
        .expect("first operation should be acknowledged");
    assert!(left.corrupt_byte(10));
    let error = counter
        .apply(operation(18, 1, 1), &mut left, &mut right)
        .expect_err("corrupt replica WAL must fail closed");
    assert!(matches!(
        error,
        Rpo0Error::ReplicaUnavailable {
            replica: "left",
            ..
        }
    ));
    assert!(counter.is_uncertain());
}
