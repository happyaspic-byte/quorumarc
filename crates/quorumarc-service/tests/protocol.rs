#![allow(clippy::expect_used)]

use ed25519_dalek::SigningKey;
use quorumarc_service::protocol::{
    ProductionFrame, ProductionFrameError, ProductionFrameKind, ProductionRequest,
};

const CLUSTER: &str = "prod-cluster";
const WORKLOAD: &str = "orders-api";
const NODE: &str = "node-a";
const KEY: &str = "node-a-2026-01";

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7_u8; 32])
}

fn request() -> ProductionRequest {
    ProductionRequest {
        cluster_id: CLUSTER.to_owned(),
        workload_id: WORKLOAD.to_owned(),
        node_id: NODE.to_owned(),
        key_id: KEY.to_owned(),
        request_id: [11; 16],
        incarnation: 1,
        epoch: 4,
        progress_commit: 12,
        policy_hash: [23; 32],
        payload: b"lease-renew".to_vec(),
    }
}

#[test]
fn production_frame_round_trips_a_signed_request() {
    let key = signing_key();
    let frame = ProductionFrame::sign(ProductionFrameKind::Request, request(), &key)
        .expect("sign production request");
    let encoded = frame.encode().expect("encode");
    let decoded = ProductionFrame::decode(&encoded).expect("decode");
    decoded
        .verify(&key.verifying_key())
        .expect("verify application signature");
    assert_eq!(decoded.kind(), ProductionFrameKind::Request);
    assert_eq!(decoded.request(), &request());
}

#[test]
fn production_frame_refuses_malformed_and_authentication_failures() {
    let key = signing_key();
    let frame = ProductionFrame::sign(ProductionFrameKind::Request, request(), &key)
        .expect("sign production request");
    let mut encoded = frame.encode().expect("encode");

    assert!(matches!(
        ProductionFrame::decode(&encoded[..encoded.len().saturating_sub(1)]),
        Err(ProductionFrameError::Malformed)
    ));

    encoded.push(0);
    assert!(matches!(
        ProductionFrame::decode(&encoded),
        Err(ProductionFrameError::Malformed)
    ));
    encoded.pop();

    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    let decoded = ProductionFrame::decode(&encoded).expect("structurally complete");
    assert!(matches!(
        decoded.verify(&key.verifying_key()),
        Err(ProductionFrameError::AuthenticationFailed)
    ));

    let other = SigningKey::from_bytes(&[9_u8; 32]);
    let decoded = ProductionFrame::decode(&frame.encode().expect("encode")).expect("decode");
    assert!(matches!(
        decoded.verify(&other.verifying_key()),
        Err(ProductionFrameError::AuthenticationFailed)
    ));
}

#[test]
fn production_frame_refuses_zero_request_id_and_empty_payload_overflow() {
    let key = signing_key();
    let mut invalid = request();
    invalid.request_id = [0; 16];
    assert!(matches!(
        ProductionFrame::sign(ProductionFrameKind::Request, invalid, &key),
        Err(ProductionFrameError::Malformed)
    ));

    let mut huge = request();
    huge.payload = vec![0; 65_537];
    assert!(matches!(
        ProductionFrame::sign(ProductionFrameKind::Request, huge, &key),
        Err(ProductionFrameError::Malformed)
    ));

    let mut zero_epoch = request();
    zero_epoch.epoch = 0;
    assert!(matches!(
        ProductionFrame::sign(ProductionFrameKind::Request, zero_epoch, &key),
        Err(ProductionFrameError::Malformed)
    ));

    let mut zero_incarnation = request();
    zero_incarnation.incarnation = 0;
    assert!(matches!(
        ProductionFrame::sign(ProductionFrameKind::Request, zero_incarnation, &key),
        Err(ProductionFrameError::Malformed)
    ));

    let mut zero_policy = request();
    zero_policy.policy_hash = [0; 32];
    assert!(matches!(
        ProductionFrame::sign(ProductionFrameKind::Request, zero_policy, &key),
        Err(ProductionFrameError::Malformed)
    ));
}
