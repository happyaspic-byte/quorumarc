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
