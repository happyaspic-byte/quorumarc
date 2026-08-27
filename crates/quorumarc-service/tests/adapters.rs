#![allow(clippy::expect_used)]

use quorumarc_service::adapters::{
    AdapterError, CloseReason, ClosedOnlyEffectAdapter, EffectAdapter, FenceAdapter, FenceRequest,
    MockEffectAdapter, MockPduFence, NodePowerState,
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
