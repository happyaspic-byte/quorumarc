#![allow(clippy::expect_used)]

use std::fs;

use quorumarc_rpo0::{
    GenericJournalError, GenericOperation, GenericSegmentManifest, SealedSegment,
};

#[test]
fn sealed_segment_seals_exact_bytes_and_manifest_matches_checksum() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-sealed-segment-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");

    let op1 = GenericOperation::new([1; 16], 0, b"entry-1").expect("op1");
    let op2 = GenericOperation::new([2; 16], 1, b"entry-2").expect("op2");
    let segment = SealedSegment::seal(1, 1, 2, &[op1, op2]).expect("seal");

    assert_eq!(segment.segment_id(), 1);
    assert_eq!(segment.start_commit(), 1);
    assert_eq!(segment.end_commit(), 2);
    assert_ne!(segment.checksum(), [0; 32]);

    let manifest = segment.manifest();
    assert_eq!(manifest.segment_id, 1);
    assert_eq!(manifest.start_commit, 1);
    assert_eq!(manifest.end_commit, 2);
    assert_eq!(manifest.checksum, segment.checksum());

    let encoded_manifest = manifest.encode();
    let decoded_manifest =
        GenericSegmentManifest::decode(&encoded_manifest).expect("decode manifest");
    assert_eq!(decoded_manifest, manifest);

    let _ = fs::remove_dir_all(directory);
}

#[test]
fn chained_sealed_segments_bind_previous_state_root() {
    let op1 = GenericOperation::new([1; 16], 0, b"entry-1").expect("op1");
    let first = SealedSegment::seal(1, 1, 1, &[op1]).expect("first segment");
    assert_eq!(first.start_commit(), 1);
    assert_eq!(first.end_commit(), 1);

    let op2 = GenericOperation::new([2; 16], 1, b"entry-2").expect("op2");
    let second = SealedSegment::seal_chained(2, 2, 2, first.final_state_root(), &[op2])
        .expect("second segment");
    assert_eq!(second.segment_id(), 2);
    assert_eq!(second.start_commit(), 2);
    assert_eq!(second.end_commit(), 2);
    assert_eq!(second.base_root(), first.final_state_root());
    assert_ne!(second.final_state_root(), first.final_state_root());
}

#[test]
fn sealed_segment_catch_up_installs_contiguous_tail_and_refuses_divergence() {
    let op1 = GenericOperation::new([1; 16], 0, b"entry-1").expect("op1");
    let first = SealedSegment::seal(1, 1, 1, &[op1]).expect("first");

    let op2 = GenericOperation::new([2; 16], 1, b"entry-2").expect("op2");
    let second =
        SealedSegment::seal_chained(2, 2, 2, first.final_state_root(), &[op2]).expect("second");

    let mut follower = quorumarc_rpo0::GenericJournal::new();
    follower.install_sealed_segment(&first).expect("catchup 1");
    assert_eq!(follower.len(), 1);
    assert_eq!(follower.recover().expect("progress").commit_index, 1);

    follower.install_sealed_segment(&second).expect("catchup 2");
    assert_eq!(follower.len(), 2);
    assert_eq!(follower.recover().expect("progress").commit_index, 2);

    let op3 = GenericOperation::new([3; 16], 2, b"entry-3").expect("op3");
    let wrong_base = SealedSegment::seal_chained(3, 3, 3, [99; 32], &[op3]).expect("wrong base");
    assert!(matches!(
        follower.install_sealed_segment(&wrong_base),
        Err(GenericJournalError::RecoveryMismatch)
    ));
    assert_eq!(follower.len(), 2);
    assert_eq!(follower.recover().expect("progress").commit_index, 2);

    let colliding_op = GenericOperation::new([2; 16], 2, b"entry-colliding").expect("op");
    let colliding_segment =
        SealedSegment::seal_chained(3, 3, 3, second.final_state_root(), &[colliding_op])
            .expect("colliding");
    assert!(matches!(
        follower.install_sealed_segment(&colliding_segment),
        Err(GenericJournalError::Corrupt)
    ));
    assert_eq!(follower.len(), 2);
    assert_eq!(follower.recover().expect("progress").commit_index, 2);
}

#[test]
fn sealed_segment_refuses_unordered_or_empty_commits() {
    assert!(matches!(
        SealedSegment::seal(1, 2, 1, &[]),
        Err(GenericJournalError::Corrupt)
    ));
    assert!(matches!(
        SealedSegment::seal(1, 1, 2, &[]),
        Err(GenericJournalError::Corrupt)
    ));
}
