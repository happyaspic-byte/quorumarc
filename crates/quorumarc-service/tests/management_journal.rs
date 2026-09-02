#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use quorumarc_service::management_journal::{
    JournalError, ManagementJournal, ManagementOperation, ManagementOutcome,
};

#[test]
fn management_journal_persists_exact_retry_and_refuses_conflicts() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-management-journal-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let identity = [7_u8; 16];
    let operation = ManagementOperation::new(1, [11; 16], [23; 32]).expect("operation");

    let mut journal = ManagementJournal::open(&directory, identity).expect("open journal");
    assert_eq!(journal.record(operation), Ok(ManagementOutcome::Committed));
    assert_eq!(
        journal.record(operation),
        Ok(ManagementOutcome::AlreadyDurable)
    );
    assert_eq!(
        journal.record(ManagementOperation::new(1, [11; 16], [24; 32]).expect("conflict")),
        Err(JournalError::ConflictingOperation)
    );
    drop(journal);

    let mut reopened = ManagementJournal::open(&directory, identity).expect("reopen journal");
    assert_eq!(reopened.highest_sequence(), 1);
    assert_eq!(
        reopened.record(ManagementOperation::new(1, [12; 16], [25; 32]).expect("stale")),
        Err(JournalError::StaleSequence)
    );
    assert_eq!(
        reopened.record(ManagementOperation::new(2, [12; 16], [25; 32]).expect("next")),
        Ok(ManagementOutcome::Committed)
    );
    assert_eq!(
        reopened.record(operation),
        Ok(ManagementOutcome::AlreadyDurable)
    );
    assert_eq!(
        reopened.record(ManagementOperation::new(3, [11; 16], [29; 32]).expect("reused id")),
        Err(JournalError::ConflictingOperation)
    );

    fs::remove_dir_all(directory).expect("remove journal fixture");
}

#[test]
fn management_journal_io_failure_poison_refuses_same_process_retry() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-management-poison-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let identity = [13_u8; 16];
    let mut journal = ManagementJournal::open(&directory, identity).expect("open journal");
    let committed = directory.join("management.journal");
    let displaced = directory.join("management.journal.displaced");
    fs::rename(&committed, &displaced).expect("displace journal");
    fs::create_dir(&committed).expect("block journal path");
    let operation = ManagementOperation::new(1, [31; 16], [41; 32]).expect("operation");

    assert_eq!(journal.record(operation), Err(JournalError::Io));
    fs::remove_dir(&committed).expect("remove blocker");
    fs::rename(&displaced, &committed).expect("restore journal");
    assert_eq!(journal.record(operation), Err(JournalError::Io));
    drop(journal);

    let mut reopened = ManagementJournal::open(&directory, identity).expect("reopen journal");
    assert_eq!(reopened.highest_sequence(), 0);
    assert_eq!(reopened.record(operation), Ok(ManagementOutcome::Committed));
    fs::remove_dir_all(directory).expect("remove journal fixture");
}

#[test]
fn management_journal_refuses_capacity_before_ack_and_remains_recoverable() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-management-capacity-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let identity = [17_u8; 16];
    let mut journal = ManagementJournal::open(&directory, identity).expect("open journal");

    for sequence in 1_u64..=11_915 {
        let mut operation_id = [0_u8; 16];
        operation_id[..8].copy_from_slice(&sequence.to_be_bytes());
        assert_eq!(
            journal.record(
                ManagementOperation::new(sequence, operation_id, [23; 32]).expect("operation")
            ),
            Ok(ManagementOutcome::Committed)
        );
    }
    let mut operation_id = [0_u8; 16];
    operation_id[..8].copy_from_slice(&11_916_u64.to_be_bytes());
    assert_eq!(
        journal
            .record(ManagementOperation::new(11_916, operation_id, [23; 32]).expect("operation")),
        Err(JournalError::Capacity)
    );
    drop(journal);

    let reopened = ManagementJournal::open(&directory, identity).expect("reopen journal");
    assert_eq!(reopened.highest_sequence(), 11_915);
    fs::remove_dir_all(directory).expect("remove journal fixture");
}

#[test]
fn management_journal_refuses_second_writer_until_first_drops() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-management-owner-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let first = ManagementJournal::open(&directory, [19; 16]).expect("first");
    assert!(matches!(
        ManagementJournal::open(&directory, [19; 16]),
        Err(JournalError::OwnerLockRefused)
    ));
    drop(first);
    assert!(ManagementJournal::open(&directory, [19; 16]).is_ok());
    fs::remove_dir_all(directory).expect("remove journal fixture");
}

#[test]
fn copied_management_journal_refuses_another_identity() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-management-identity-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let journal = ManagementJournal::open(&directory, [7; 16]).expect("create journal");
    drop(journal);
    assert!(matches!(
        ManagementJournal::open(&directory, [8; 16]),
        Err(JournalError::IdentityMismatch)
    ));
    fs::remove_dir_all(directory).expect("remove journal fixture");
}

#[test]
fn management_journal_refuses_symlink_and_group_accessible_files() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-management-security-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create journal fixture");
    let outside = directory.join("outside.journal");
    fs::write(&outside, b"dummy").expect("write");
    let link = directory.join("management.journal");
    symlink(&outside, &link).expect("symlink");
    assert!(matches!(
        ManagementJournal::open(&directory, [7; 16]),
        Err(JournalError::Corrupt)
    ));
    let _ = fs::remove_file(&link);

    let journal = ManagementJournal::open(&directory, [7; 16]).expect("create");
    drop(journal);
    fs::set_permissions(&link, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(matches!(
        ManagementJournal::open(&directory, [7; 16]),
        Err(JournalError::Corrupt)
    ));
    let _ = fs::remove_dir_all(directory);
}
