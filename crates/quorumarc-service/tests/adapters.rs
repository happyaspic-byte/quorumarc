#![allow(clippy::expect_used)]

use ed25519_dalek::SigningKey;
use quorumarc_service::adapters::{
    AdapterError, CloseReason, ClosedOnlyEffectAdapter, EffectAdapter, FenceAdapter, FenceRequest,
    MockEffectAdapter, MockPduFence, NodePowerState, SystemdWorkloadAdapter, VipAdapter, VipState,
    WorkloadHealth,
};

#[test]
fn mock_pdu_refuses_wrong_target_and_requires_independent_read_back() {
    let mut fence = MockPduFence::new([("node-a", "outlet-1"), ("node-b", "outlet-2")]);
    fence.set_power("outlet-1", NodePowerState::On);
    fence.set_power("outlet-2", NodePowerState::On);

    assert!(matches!(
        fence.fence(FenceRequest {
            target: "node-c",
            expected_outlet: "outlet-1",
            challenge: [3; 16],
        }),
        Err(AdapterError::WrongTarget)
    ));
    assert!(matches!(
        fence.fence(FenceRequest {
            target: "node-a",
            expected_outlet: "outlet-2",
            challenge: [3; 16],
        }),
        Err(AdapterError::WrongTarget)
    ));

    let evidence = fence
        .fence(FenceRequest {
            target: "node-a",
            expected_outlet: "outlet-1",
            challenge: [9; 16],
        })
        .expect("fence");
    fence.set_read_back("outlet-1", NodePowerState::On);
    assert!(matches!(
        fence.verify(&evidence),
        Err(AdapterError::ReadBackMismatch)
    ));
    fence.set_read_back("outlet-1", NodePowerState::Off);
    fence.verify(&evidence).expect("independent off read-back");
}

#[test]
fn effect_adapter_stays_closed_until_continuity_receipt_and_closes_on_expiry() {
    let mut adapter = MockEffectAdapter::closed();
    adapter.verify_closed().expect("starts closed");
    assert!(matches!(
        adapter.open("orders-api", 2),
        Err(AdapterError::ReceiptRequired)
    ));
    adapter
        .open_with_receipt("orders-api", 2, [11; 32])
        .expect("open with receipt");
    adapter.close(CloseReason::LeaseExpired).expect("close");
    adapter.verify_closed().expect("closed after expiry");
}

#[test]
fn closed_only_effect_adapter_never_opens_even_with_a_receipt() {
    let mut adapter = ClosedOnlyEffectAdapter;
    adapter.verify_closed().expect("starts closed");
    assert!(matches!(
        adapter.open_with_receipt("orders-api", 2, [11; 32]),
        Err(AdapterError::ReceiptRequired)
    ));
    adapter.verify_closed().expect("still closed");
}

#[test]
fn mock_pdu_signed_receipt_requires_independent_off_read_back() {
    let mut fence = MockPduFence::new([("node-a", "outlet-1"), ("node-b", "outlet-2")]);
    fence.set_power("outlet-1", NodePowerState::On);
    let evidence = fence
        .fence(FenceRequest {
            target: "node-a",
            expected_outlet: "outlet-1",
            challenge: [9; 16],
        })
        .expect("fence");
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    fence.set_read_back("outlet-1", NodePowerState::On);
    assert!(matches!(
        fence.signed_receipt(&evidence, &signing_key),
        Err(AdapterError::ReadBackMismatch)
    ));
    fence.set_read_back("outlet-1", NodePowerState::Off);
    let receipt = fence
        .signed_receipt(&evidence, &signing_key)
        .expect("receipt");
    assert_eq!(receipt.target(), "node-a");
    assert_eq!(receipt.outlet(), "outlet-1");
    assert_eq!(receipt.challenge(), [9; 16]);
    assert_ne!(receipt.digest(), [0; 32]);
    receipt
        .verify(&signing_key.verifying_key())
        .expect("verify signature");

    let other_key = SigningKey::from_bytes(&[8; 32]);
    assert!(receipt.verify(&other_key.verifying_key()).is_err());

    fence.set_power("outlet-1", NodePowerState::On);
    let other = fence
        .fence(FenceRequest {
            target: "node-a",
            expected_outlet: "outlet-1",
            challenge: [8; 16],
        })
        .expect("other fence");
    fence.set_read_back("outlet-1", NodePowerState::Off);
    let other_receipt = fence
        .signed_receipt(&other, &signing_key)
        .expect("other receipt");
    assert_ne!(receipt.digest(), other_receipt.digest());
    assert_ne!(receipt.signature(), other_receipt.signature());
}

#[test]
fn vip_adapter_attaches_only_with_receipt_and_detaches_on_expiry() {
    let mut vip = VipAdapter::new("172.30.1.100/24", "enp1s0");
    assert_eq!(vip.state(), VipState::Detached);
    assert!(matches!(
        vip.attach(2, [0; 32]),
        Err(AdapterError::ReceiptRequired)
    ));
    assert_eq!(vip.state(), VipState::Detached);

    vip.attach(2, [11; 32]).expect("attach");
    assert_eq!(vip.state(), VipState::Attached(2));

    vip.detach(CloseReason::LeaseExpired).expect("detach");
    assert_eq!(vip.state(), VipState::Detached);
}

#[test]
fn systemd_workload_adapter_demands_health_and_closes_before_drain() {
    let mut workload = SystemdWorkloadAdapter::new("orders-api.service");
    assert_eq!(workload.health(), WorkloadHealth::Stopped);
    assert!(matches!(
        workload.activate(2),
        Err(AdapterError::EffectNotClosed)
    ));

    workload.set_service_running(true);
    assert_eq!(workload.health(), WorkloadHealth::Healthy);
    workload.activate(2).expect("activate");
    assert_eq!(workload.active_epoch(), Some(2));

    workload.drain().expect("drain");
    assert_eq!(workload.active_epoch(), None);
}
