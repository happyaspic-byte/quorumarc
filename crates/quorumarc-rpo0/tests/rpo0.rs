#![allow(clippy::expect_used, clippy::panic)]

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_rpo0::{
    CounterOperation, Fault, FileReplica, MemoryReplica, OperationId, OperationPreflight,
    ReplicaSink, ReplicatedCounter, Rpo0Error, WalCorruption, WalEntry, recover_wal,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn operation(id: u8, expected_commit_index: u64, increment: u64) -> CounterOperation {
    CounterOperation {
        id: OperationId::new([id; 16]),
        expected_commit_index,
        increment,
    }
}

#[test]
fn preflight_classifies_exact_fresh_and_logical_refusals_without_io() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    assert!(matches!(
        counter.preflight(operation(1, 0, 5)),
        Ok(OperationPreflight::Fresh)
    ));
    let acknowledged = counter
        .apply(operation(1, 0, 5), &mut left, &mut right)
        .expect("first write should be acknowledged");
    match counter.preflight(operation(1, 0, 5)) {
        Ok(OperationPreflight::Exact(exact)) => assert_eq!(exact, acknowledged),
        other => panic!("expected exact acknowledgement, got {other:?}"),
    }
    assert!(matches!(
        counter.preflight(operation(1, 0, 7)),
        Err(Rpo0Error::ConflictingDuplicate(_))
    ));
    assert!(matches!(
        counter.preflight(operation(2, 0, 1)),
        Err(Rpo0Error::StaleOperation {
            expected: 0,
            actual: 1
        })
    ));
    assert!(matches!(
        counter.preflight(operation(2, 2, 1)),
        Err(Rpo0Error::OutOfOrderOperation {
            expected: 2,
            actual: 1
        })
    ));
    assert_eq!(left.append_count(), 1);
    assert_eq!(right.append_count(), 1);
}

#[test]
fn recovered_counter_uses_configured_replica_ids_for_exact_retry() {
    let mut original = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    original
        .apply(operation(21, 0, 2), &mut left, &mut right)
        .expect("write should be acknowledged");
    let recovered = recover_wal(left.bytes()).expect("WAL should recover");
    let restarted = ReplicatedCounter::from_recovered_with_replica_ids(
        recovered.clone(),
        recovered,
        "node-a",
        "node-b",
    )
    .expect("matching replicas should recover");
    match restarted.preflight(operation(21, 0, 2)) {
        Ok(OperationPreflight::Exact(acknowledgement)) => {
            assert_eq!(acknowledgement.replica_receipts[0].replica_id, "node-a");
            assert_eq!(acknowledgement.replica_receipts[1].replica_id, "node-b");
        }
        other => panic!("expected reconstructed exact acknowledgement, got {other:?}"),
    }
}

#[test]
fn record_capacity_refuses_fresh_1025th_write_before_replica_io() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    for index in 0..quorumarc_rpo0::MAX_WAL_RECORDS {
        let id = u8::try_from(index % 251 + 1).expect("bounded operation byte");
        let mut bytes = [id; 16];
        bytes[8..].copy_from_slice(&index.to_be_bytes());
        counter
            .apply(
                CounterOperation {
                    id: OperationId::new(bytes),
                    expected_commit_index: index,
                    increment: 1,
                },
                &mut left,
                &mut right,
            )
            .expect("bounded write should be acknowledged");
    }
    let left_count = left.append_count();
    let right_count = right.append_count();
    assert!(matches!(
        counter.preflight(operation(250, quorumarc_rpo0::MAX_WAL_RECORDS, 1)),
        Err(Rpo0Error::CapacityExceeded)
    ));
    assert!(matches!(
        counter.apply(
            operation(250, quorumarc_rpo0::MAX_WAL_RECORDS, 1),
            &mut left,
            &mut right
        ),
        Err(Rpo0Error::CapacityExceeded)
    ));
    assert_eq!(left.append_count(), left_count);
    assert_eq!(right.append_count(), right_count);
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
fn replica_retry_after_lost_response_returns_same_durable_receipt() {
    let entry = WalEntry {
        commit_index: 1,
        operation_id: OperationId::new([41; 16]),
        previous_value: 0,
        increment: 3,
        value: 3,
    };
    let record = entry.encode();
    let mut replica = MemoryReplica::new("node-b");
    let first = replica
        .append_and_flush(&entry, &record)
        .expect("first append should become durable");
    let retry = replica
        .append_and_flush(&entry, &record)
        .expect("exact retry should return the durable receipt");

    assert_eq!(first, retry);
    assert_eq!(replica.bytes(), record);
}

#[test]
fn file_replica_exact_tail_retry_does_not_append_twice() {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-rpo0-tail-retry-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("temporary directory should be created");
    let path = directory.join("replica.wal");
    let entry = WalEntry {
        commit_index: 1,
        operation_id: OperationId::new([43; 16]),
        previous_value: 0,
        increment: 4,
        value: 4,
    };
    let record = entry.encode();
    let mut replica = FileReplica::new("node-b", &path);
    let first = replica
        .append_and_flush(&entry, &record)
        .expect("first file append should become durable");
    let retry = replica
        .append_and_flush(&entry, &record)
        .expect("exact file retry should be idempotent");

    assert_eq!(first, retry);
    assert_eq!(fs::read(&path).expect("WAL should be readable"), record);
    fs::remove_dir_all(directory).expect("temporary directory should be removed");
}

#[test]
fn replica_rejects_noncanonical_bytes_before_append() {
    let entry = WalEntry {
        commit_index: 1,
        operation_id: OperationId::new([42; 16]),
        previous_value: 0,
        increment: 3,
        value: 3,
    };
    let mut changed = entry.encode();
    changed[0] ^= 0xff;
    let mut replica = MemoryReplica::new("node-b");

    assert!(matches!(
        replica.append_and_flush(&entry, &changed),
        Err(quorumarc_rpo0::ReplicaError::InvalidReceipt)
    ));
    assert!(replica.bytes().is_empty());
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
fn recovered_wal_confirms_only_the_exact_stable_operation() {
    let mut counter = ReplicatedCounter::new();
    let mut left = MemoryReplica::new("left");
    let mut right = MemoryReplica::new("right");
    let acknowledged = counter
        .apply(operation(19, 0, 4), &mut left, &mut right)
        .expect("operation should be acknowledged");
    let recovered = recover_wal(left.bytes()).expect("WAL should recover");
    let confirmed = recovered
        .confirm_operation(operation(19, 0, 4))
        .expect("exact recovered retry")
        .expect("operation must exist");
    assert_eq!(confirmed.operation_id, OperationId::new([19; 16]));
    assert_eq!(confirmed.commit_index, acknowledged.commit_index);
    assert_eq!(confirmed.value, acknowledged.value);
    assert_eq!(confirmed.state_root, acknowledged.state_root);
    assert!(
        recovered
            .confirm_operation(operation(20, 0, 4))
            .expect("unknown operation is not an error")
            .is_none()
    );
    assert!(matches!(
        recovered.confirm_operation(operation(19, 0, 5)),
        Err(Rpo0Error::ConflictingDuplicate(_))
    ));
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
