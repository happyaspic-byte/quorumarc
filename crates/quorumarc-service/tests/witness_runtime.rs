#![allow(clippy::expect_used)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use quorumarc_service::management_journal::ManagementOutcome;
use quorumarc_service::protocol::{
    AdmissionError, ProductionFrame, ProductionFrameKind, ProductionRequest,
};
use quorumarc_service::witness::{
    ProductionWitnessRuntime, WitnessMembership, WitnessMembershipError,
};

#[test]
fn witness_membership_requires_two_data_nodes_and_independent_witness() {
    let membership = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 23], 7602)),
        "power-w",
    );
    assert!(membership.is_ok());

    assert!(matches!(
        WitnessMembership::new(
            "node-a",
            SocketAddr::from(([172, 30, 1, 22], 7601)),
            "power-a",
            "node-b",
            SocketAddr::from(([172, 30, 1, 21], 7601)),
            "power-b",
            "witness-a",
            SocketAddr::from(([172, 30, 1, 22], 7602)),
            "power-w",
        ),
        Err(WitnessMembershipError::SharedHost)
    ));

    let mapped_shared = WitnessMembership::new(
        "node-a",
        SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(172, 30, 1, 22).to_ipv6_mapped()),
            7601,
        ),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 22], 7602)),
        "power-w",
    );
    assert!(matches!(
        mapped_shared,
        Err(WitnessMembershipError::SharedHost)
    ));

    let shared_data_host = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 22], 7609)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 23], 7602)),
        "power-w",
    );
    assert!(matches!(
        shared_data_host,
        Err(WitnessMembershipError::SharedHost)
    ));
}

#[test]
fn witness_membership_refuses_reserved_host_and_duplicate_nodes() {
    let reserved = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 84], 7602)),
        "power-w",
    );
    assert!(matches!(
        reserved,
        Err(WitnessMembershipError::ReservedWitnessHost)
    ));

    let mapped_reserved = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(172, 30, 1, 84).to_ipv6_mapped()),
            7602,
        ),
        "power-w",
    );
    assert!(matches!(
        mapped_reserved,
        Err(WitnessMembershipError::ReservedWitnessHost)
    ));

    let same_candidate = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-a",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 23], 7602)),
        "power-w",
    );
    assert!(matches!(
        same_candidate,
        Err(WitnessMembershipError::DuplicateMember)
    ));
}

fn signed_request(
    sequence: u64,
    request_id: [u8; 16],
    payload: &[u8],
    key: &SigningKey,
) -> Vec<u8> {
    ProductionFrame::sign(
        ProductionFrameKind::Request,
        ProductionRequest {
            cluster_id: "prod-cluster".to_owned(),
            workload_id: "orders-api".to_owned(),
            node_id: "node-a".to_owned(),
            key_id: "node-a-2026-01".to_owned(),
            request_id,
            sequence,
            incarnation: 1,
            epoch: 4,
            progress_commit: 12,
            policy_hash: [23; 32],
            payload: payload.to_vec(),
        },
        key,
    )
    .expect("sign")
    .encode()
    .expect("encode")
}

#[test]
fn production_witness_records_authenticated_votes_durably_and_restarts_closed() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-witness-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let first = signed_request(1, [11; 16], b"vote", &key);

    let mut runtime = ProductionWitnessRuntime::open(
        &directory,
        [41; 16],
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("open");
    assert!(!runtime.effects_open());
    assert_eq!(runtime.admit_vote(&first), Ok(ManagementOutcome::Committed));
    assert_eq!(runtime.highest_sequence(), 1);
    drop(runtime);

    let mut resumed = ProductionWitnessRuntime::open(
        &directory,
        [41; 16],
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("resume");
    assert!(!resumed.effects_open());
    assert_eq!(
        resumed.admit_vote(&first),
        Ok(ManagementOutcome::AlreadyDurable)
    );
    assert_eq!(resumed.highest_sequence(), 1);
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_witness_refuses_response_frames_and_authentication_failure() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-witness-refusal-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let key = SigningKey::from_bytes(&[7_u8; 32]);
    let other = SigningKey::from_bytes(&[9_u8; 32]);
    let mut runtime = ProductionWitnessRuntime::open(
        &directory,
        [42; 16],
        "prod-cluster",
        "orders-api",
        "node-a",
        "node-a-2026-01",
        key.verifying_key(),
    )
    .expect("open");

    let response = ProductionFrame::sign(
        ProductionFrameKind::Response,
        ProductionRequest {
            cluster_id: "prod-cluster".to_owned(),
            workload_id: "orders-api".to_owned(),
            node_id: "node-a".to_owned(),
            key_id: "node-a-2026-01".to_owned(),
            request_id: [12; 16],
            sequence: 1,
            incarnation: 1,
            epoch: 4,
            progress_commit: 12,
            policy_hash: [23; 32],
            payload: b"response".to_vec(),
        },
        &key,
    )
    .expect("sign")
    .encode()
    .expect("encode");
    assert_eq!(
        runtime.admit_vote(&response),
        Err(AdmissionError::Malformed)
    );
    assert_eq!(
        runtime.admit_vote(&signed_request(1, [13; 16], b"vote", &other)),
        Err(AdmissionError::AuthenticationFailed)
    );
    assert_eq!(runtime.highest_sequence(), 0);
    assert!(!runtime.effects_open());
    let _ = fs::remove_dir_all(directory);
}
