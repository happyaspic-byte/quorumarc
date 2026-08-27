#![allow(clippy::expect_used)]

use std::fs;

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
