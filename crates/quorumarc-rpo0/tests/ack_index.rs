#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::symlink;

use quorumarc_rpo0::{
    AckIndexError, AcknowledgedWrite, DurableAckIndex, DurableReceipt, OperationId,
};

fn acknowledgement(id: u8, commit_index: u64) -> AcknowledgedWrite {
    AcknowledgedWrite {
        operation_id: OperationId::new([id; 16]),
        commit_index,
        value: commit_index * 10,
        state_root: [id; 32],
        replica_receipts: [
            DurableReceipt {
                replica_id: "node-a".to_owned(),
                commit_index,
                record_checksum: u32::from(id),
            },
            DurableReceipt {
                replica_id: "node-b".to_owned(),
                commit_index,
                record_checksum: u32::from(id) + 1,
            },
        ],
    }
}

#[test]
fn durable_ack_index_recovers_exact_acknowledgements_after_restart() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-ack-index-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("client-acks.index");
    let ack = acknowledgement(7, 42);

    let mut index = DurableAckIndex::open(&path).expect("open");
    assert_eq!(index.get(ack.operation_id), None);
    index.record(&ack).expect("record");
    assert_eq!(index.get(ack.operation_id), Some(&ack));
    drop(index);

    let resumed = DurableAckIndex::open(&path).expect("resume");
    assert_eq!(resumed.get(ack.operation_id), Some(&ack));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn durable_ack_index_is_idempotent_and_rejects_conflicting_operation_ids() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-ack-conflict-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("client-acks.index");
    let ack = acknowledgement(9, 11);
    let mut conflicting = ack.clone();
    conflicting.value = 999;

    let mut index = DurableAckIndex::open(&path).expect("open");
    index.record(&ack).expect("record");
    index.record(&ack).expect("exact retry");
    assert!(matches!(
        index.record(&conflicting),
        Err(AckIndexError::ConflictingOperation)
    ));
    assert_eq!(index.len(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn durable_ack_index_refuses_torn_or_corrupt_records() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-ack-corrupt-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("client-acks.index");
    let ack = acknowledgement(12, 15);
    let mut index = DurableAckIndex::open(&path).expect("open");
    index.record(&ack).expect("record");
    drop(index);

    let mut bytes = fs::read(&path).expect("read");
    bytes.pop();
    fs::write(&path, &bytes).expect("truncate");
    assert!(matches!(
        DurableAckIndex::open(&path),
        Err(AckIndexError::Corrupt)
    ));

    fs::write(&path, vec![0_u8; 1_048_577]).expect("oversize");
    assert!(matches!(
        DurableAckIndex::open(&path),
        Err(AckIndexError::TooLarge)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn durable_ack_index_refuses_append_that_exceeds_recovery_limit() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-ack-limit-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let path = directory.join("client-acks.index");
    fs::write(&path, vec![0_u8; 1_048_560]).expect("near limit");

    let error = DurableAckIndex::open(&path).expect_err("invalid records remain corrupt");
    assert_eq!(error, AckIndexError::Corrupt);

    fs::remove_file(&path).expect("remove invalid index");
    let mut index = DurableAckIndex::open(&path).expect("open");
    let ack = acknowledgement(13, 16);
    index.record(&ack).expect("first record");
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open for extension");
    file.set_len(1_048_576).expect("extend to limit");
    assert!(matches!(
        index.record(&acknowledgement(14, 17)),
        Err(AckIndexError::TooLarge)
    ));
    assert_eq!(fs::metadata(&path).expect("metadata").len(), 1_048_576);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn durable_ack_index_refuses_symlinks() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-ack-symlink-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let outside = directory.join("outside.index");
    fs::write(&outside, b"").expect("outside");
    let path = directory.join("client-acks.index");
    symlink(&outside, &path).expect("symlink");

    assert!(matches!(
        DurableAckIndex::open(&path),
        Err(AckIndexError::Corrupt)
    ));
    let _ = fs::remove_dir_all(directory);
}
