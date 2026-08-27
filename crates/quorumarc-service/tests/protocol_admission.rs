#![allow(clippy::expect_used)]

use std::fs;

use ed25519_dalek::SigningKey;
use quorumarc_service::management_journal::{ManagementJournal, ManagementOutcome};
use quorumarc_service::protocol::{
    AdmissionError, AuthenticatedRequestJournal, ProductionFrame, ProductionFrameKind,
    ProductionRequest,
};

fn request(sequence: u64, payload: &[u8]) -> ProductionRequest {
    ProductionRequest {
        cluster_id: "prod-cluster".to_owned(),
        workload_id: "orders-api".to_owned(),
        node_id: "node-a".to_owned(),
        key_id: "node-a-2026-01".to_owned(),
        request_id: [11; 16],
        sequence,
        incarnation: 1,
        epoch: 4,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: payload.to_vec(),
    }
}

#[test]
fn authenticated_request_is_durable_before_execution_and_exact_retry_is_stable() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-protocol-admission-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let journal = ManagementJournal::open(&directory, [7; 16]).expect("journal");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let frame = ProductionFrame::sign(ProductionFrameKind::Request, request(1, b"lease"), &key)
        .expect("sign");
    let encoded = frame.encode().expect("encode");
    let mut admission =
        AuthenticatedRequestJournal::new(journal, "node-a", "node-a-2026-01", key.verifying_key());

    assert_eq!(admission.admit(&encoded), Ok(ManagementOutcome::Committed));
    assert_eq!(admission.highest_sequence(), 1);
    assert_eq!(
        admission.admit(&encoded),
        Ok(ManagementOutcome::AlreadyDurable)
    );
    assert_eq!(admission.highest_sequence(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn authentication_and_malformed_failures_do_not_advance_or_suspect_node_failure() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-protocol-refusal-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let journal = ManagementJournal::open(&directory, [8; 16]).expect("journal");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[9_u8; 32]);
    let mut admission =
        AuthenticatedRequestJournal::new(journal, "node-a", "node-a-2026-01", key.verifying_key());

    let wrong_key =
        ProductionFrame::sign(ProductionFrameKind::Request, request(1, b"lease"), &other)
            .expect("sign")
            .encode()
            .expect("encode");
    let authentication = admission.admit(&wrong_key).expect_err("auth refusal");
    assert_eq!(authentication, AdmissionError::AuthenticationFailed);
    assert!(!authentication.is_node_failure_suspicion());
    assert_eq!(admission.highest_sequence(), 0);

    let malformed = admission.admit(b"not-a-frame").expect_err("malformed");
    assert_eq!(malformed, AdmissionError::Malformed);
    assert!(!malformed.is_node_failure_suspicion());
    assert_eq!(admission.highest_sequence(), 0);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn authenticated_conflict_and_future_sequence_fail_closed() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-protocol-conflict-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let journal = ManagementJournal::open(&directory, [9; 16]).expect("journal");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let mut admission =
        AuthenticatedRequestJournal::new(journal, "node-a", "node-a-2026-01", key.verifying_key());

    let first = ProductionFrame::sign(ProductionFrameKind::Request, request(1, b"lease"), &key)
        .expect("sign")
        .encode()
        .expect("encode");
    admission.admit(&first).expect("first");

    let conflict =
        ProductionFrame::sign(ProductionFrameKind::Request, request(1, b"changed"), &key)
            .expect("sign")
            .encode()
            .expect("encode");
    assert_eq!(
        admission.admit(&conflict),
        Err(AdmissionError::ReplayRefused)
    );

    let mut future_request = request(3, b"future");
    future_request.request_id = [12; 16];
    let future = ProductionFrame::sign(ProductionFrameKind::Request, future_request, &key)
        .expect("sign")
        .encode()
        .expect("encode");
    assert_eq!(admission.admit(&future), Err(AdmissionError::ReplayRefused));
    assert_eq!(admission.highest_sequence(), 1);
    let _ = fs::remove_dir_all(directory);
}
