#![allow(clippy::expect_used)]

use std::fs;

use ed25519_dalek::SigningKey;
use quorumarc_service::controller::{DurableController, SwitchRole};
use quorumarc_service::management_journal::ManagementOutcome;
use quorumarc_service::protocol::{
    AdmissionError, ProductionFrame, ProductionFrameKind, ProductionRequest,
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

fn encoded(sequence: u64, payload: &[u8], key: &SigningKey) -> Vec<u8> {
    ProductionFrame::sign(
        ProductionFrameKind::Request,
        request(sequence, payload),
        key,
    )
    .expect("sign")
    .encode()
    .expect("encode")
}

#[test]
fn durable_controller_records_request_before_execution_and_resumes_after_restart() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-controller-persist-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let first = encoded(1, b"lease", &key);

    let mut controller = DurableController::open(
        &directory,
        [7; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
        SwitchRole::NodeA,
        SwitchRole::NodeB,
    )
    .expect("open");
    assert_eq!(controller.accept(&first), Ok(ManagementOutcome::Committed));
    assert_eq!(controller.highest_sequence(), 1);
    assert!(!controller.effects_open());
    drop(controller);

    let mut resumed = DurableController::open(
        &directory,
        [7; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
        SwitchRole::NodeA,
        SwitchRole::NodeB,
    )
    .expect("resume");
    assert_eq!(resumed.highest_sequence(), 1);
    assert!(!resumed.effects_open());
    assert_eq!(
        resumed.accept(&first),
        Ok(ManagementOutcome::AlreadyDurable)
    );
    assert!(!resumed.effects_open());
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn durable_controller_refuses_stale_replay_without_suspecting_node_failure() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-controller-replay-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[9_u8; 32]);

    let mut controller = DurableController::open(
        &directory,
        [8; 16],
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
        SwitchRole::NodeA,
        SwitchRole::NodeB,
    )
    .expect("open");
    controller
        .accept(&encoded(1, b"lease", &key))
        .expect("first");

    let conflict = controller
        .accept(&encoded(1, b"changed", &key))
        .expect_err("conflict");
    assert_eq!(conflict, AdmissionError::ReplayRefused);
    assert!(!conflict.is_node_failure_suspicion());

    let authentication = controller
        .accept(&encoded(2, b"next", &other))
        .expect_err("auth");
    assert_eq!(authentication, AdmissionError::AuthenticationFailed);
    assert!(!authentication.is_node_failure_suspicion());
    assert_eq!(controller.highest_sequence(), 1);
    assert!(!controller.effects_open());
    let _ = fs::remove_dir_all(directory);
}
