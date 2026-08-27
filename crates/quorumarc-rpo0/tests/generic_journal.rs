#![allow(clippy::expect_used)]

use quorumarc_rpo0::{GenericJournal, GenericJournalError, GenericOperation};

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
