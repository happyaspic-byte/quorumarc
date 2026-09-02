#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use ed25519_dalek::SigningKey;
use quorumarc_service::controller::{
    DurableController, DurableProgressLease, ProgressLeaseError, SwitchRole,
};
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
        "prod-cluster",
        "orders-api",
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
        "prod-cluster",
        "orders-api",
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
        "prod-cluster",
        "orders-api",
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

#[test]
fn progress_lease_renews_only_after_new_durable_progress_and_survives_restart() {
    let directory =
        std::env::temp_dir().join(format!("quorumarc-progress-lease-{}", std::process::id()));
    fs::create_dir_all(&directory).expect("directory");
    let mut lease = DurableProgressLease::open(&directory, [31; 16]).expect("open");

    assert_eq!(lease.expires_at_ms(), None);
    assert_eq!(lease.observe_heartbeat(100), None);
    assert_eq!(lease.expires_at_ms(), None);
    assert_eq!(lease.record_progress(12, 100, 50), Ok(150));
    assert_eq!(lease.expires_at_ms(), Some(150));
    assert_eq!(lease.observe_heartbeat(120), Some(150));
    assert_eq!(
        lease.record_progress(12, 120, 50),
        Err(ProgressLeaseError::ProgressNotAdvanced)
    );
    assert_eq!(lease.expires_at_ms(), Some(150));
    drop(lease);

    let resumed = DurableProgressLease::open(&directory, [31; 16]).expect("resume");
    assert_eq!(resumed.highest_progress_commit(), 12);
    assert_eq!(resumed.expires_at_ms(), Some(150));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn progress_lease_compacts_before_its_own_recovery_limit() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-progress-compaction-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let mut lease = DurableProgressLease::open(&directory, [36; 16]).expect("open");
    for commit in 1..=2_000 {
        lease
            .record_progress(commit, commit * 10, 10)
            .expect("record");
    }
    drop(lease);

    let resumed = DurableProgressLease::open(&directory, [36; 16]).expect("resume");
    assert_eq!(resumed.highest_progress_commit(), 2_000);
    assert_eq!(resumed.expires_at_ms(), Some(20_010));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn progress_lease_refuses_clock_overflow_and_copied_identity() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-progress-overflow-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let mut lease = DurableProgressLease::open(&directory, [32; 16]).expect("open");
    assert_eq!(
        lease.record_progress(1, u64::MAX, 1),
        Err(ProgressLeaseError::ClockOverflow)
    );
    assert_eq!(lease.expires_at_ms(), None);
    drop(lease);
    assert!(matches!(
        DurableProgressLease::open(&directory, [33; 16]),
        Err(ProgressLeaseError::IdentityMismatch)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn progress_lease_refuses_symlink_and_group_accessible_files() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-progress-security-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let outside = directory.join("outside.lease");
    fs::write(&outside, b"dummy").expect("write");
    let link = directory.join("progress.lease");
    symlink(&outside, &link).expect("symlink");
    assert!(matches!(
        DurableProgressLease::open(&directory, [34; 16]),
        Err(ProgressLeaseError::Corrupt)
    ));
    let _ = fs::remove_file(&link);

    let mut lease = DurableProgressLease::open(&directory, [35; 16]).expect("create");
    lease.record_progress(1, 10, 10).expect("record");
    drop(lease);
    fs::set_permissions(&link, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(matches!(
        DurableProgressLease::open(&directory, [35; 16]),
        Err(ProgressLeaseError::Corrupt)
    ));
    let _ = fs::remove_dir_all(directory);
}
