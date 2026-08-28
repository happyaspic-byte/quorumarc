#![allow(clippy::expect_used)]

use ed25519_dalek::SigningKey;
use quorumarc_service::adapters::{
    AdapterError, CloseReason, ClosedOnlyEffectAdapter, EffectAdapter, FenceAdapter, FenceRequest,
    MockEffectAdapter, MockPduFence, NodePowerState, SystemdWorkloadAdapter, VipAdapter, VipState,
    WorkloadHealth,
};
use quorumarc_service::linux_vip::{
    EffectOpenAuthorization, LinuxVipEffectAdapter, VipBackend, VipBackendError, VipObservation,
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

#[derive(Debug, Default)]
struct FakeVipBackend {
    observation: Option<VipObservation>,
    adds: usize,
    deletes: usize,
    fail_add: bool,
    fail_observe: bool,
    fail_delete: bool,
}

impl VipBackend for FakeVipBackend {
    fn observe(
        &mut self,
        _interface: &str,
        _address: std::net::IpAddr,
        _prefix_len: u8,
    ) -> Result<Option<VipObservation>, VipBackendError> {
        if self.fail_observe {
            return Err(VipBackendError::Io);
        }
        Ok(self.observation.clone())
    }

    fn add(&mut self, observation: &VipObservation) -> Result<(), VipBackendError> {
        self.adds += 1;
        if self.fail_add {
            return Err(VipBackendError::PermissionDenied);
        }
        self.observation = Some(observation.clone());
        Ok(())
    }

    fn delete(&mut self, observation: &VipObservation) -> Result<(), VipBackendError> {
        self.deletes += 1;
        if self.fail_delete {
            return Err(VipBackendError::Io);
        }
        if self.observation.as_ref() == Some(observation) {
            self.observation = None;
        }
        Ok(())
    }
}

fn authorization(epoch: u64) -> EffectOpenAuthorization {
    EffectOpenAuthorization::new("orders-api", "node-a", epoch, [11; 32]).expect("authorization")
}

#[test]
fn linux_vip_requires_bound_authorization_and_kernel_read_back() {
    let backend = FakeVipBackend::default();
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");

    let wrong =
        EffectOpenAuthorization::new("other", "node-a", 2, [11; 32]).expect("wrong authorization");
    assert_eq!(adapter.attach(&wrong), Err(AdapterError::WrongTarget));
    assert_eq!(adapter.backend().adds, 0);

    adapter.attach(&authorization(2)).expect("attach");
    assert_eq!(adapter.state(), VipState::Attached(2));
    assert_eq!(adapter.backend().adds, 1);
    assert!(adapter.verify_attached().is_ok());
}

#[test]
fn linux_vip_refuses_foreign_address_and_deletes_owned_address_only() {
    let backend = FakeVipBackend {
        observation: Some(VipObservation::foreign(
            "enp1s0",
            "172.30.1.100".parse().expect("ip"),
            24,
        )),
        ..FakeVipBackend::default()
    };
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");

    assert_eq!(
        adapter.attach(&authorization(2)),
        Err(AdapterError::ReadBackMismatch)
    );
    assert_eq!(adapter.backend().adds, 0);
    assert_eq!(adapter.backend().deletes, 0);

    adapter.backend_mut().observation = None;
    adapter.attach(&authorization(2)).expect("attach owned");
    adapter
        .detach(CloseReason::LeaseExpired)
        .expect("detach owned");
    assert_eq!(adapter.state(), VipState::Detached);
    assert_eq!(adapter.backend().deletes, 1);
}

#[test]
fn linux_vip_rolls_back_when_add_read_back_is_not_owned() {
    let backend = FakeVipBackend::default();
    let mut adapter = LinuxVipEffectAdapter::new(
        "orders-api",
        "node-a",
        "2001:db8::100/64",
        "enp1s0",
        backend,
    )
    .expect("adapter");
    adapter.backend_mut().fail_add = true;

    assert_eq!(
        adapter.attach(&authorization(2)),
        Err(AdapterError::EffectNotClosed)
    );
    assert_eq!(adapter.state(), VipState::Detached);
}

#[test]
fn linux_vip_adopts_pre_existing_owned_address_without_re_adding_or_deleting() {
    let backend = FakeVipBackend {
        observation: Some(VipObservation::owned(
            "enp1s0",
            "172.30.1.100".parse().expect("ip"),
            24,
        )),
        ..FakeVipBackend::default()
    };
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");

    adapter
        .attach(&authorization(3))
        .expect("adopt pre-existing owned");
    assert_eq!(adapter.state(), VipState::Attached(3));
    assert_eq!(adapter.backend().adds, 0);
    assert_eq!(adapter.backend().deletes, 0);
}

#[test]
fn linux_vip_same_epoch_attach_verifies_kernel_presence_before_success() {
    let backend = FakeVipBackend::default();
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");
    adapter.attach(&authorization(2)).expect("first attach");
    assert_eq!(adapter.state(), VipState::Attached(2));

    // External removal of VIP while in Attached state
    adapter.backend_mut().observation = None;
    assert_eq!(
        adapter.attach(&authorization(2)),
        Err(AdapterError::EffectNotClosed)
    );
    assert_eq!(adapter.state(), VipState::Detached);
}

#[test]
fn linux_vip_rejects_stale_epoch_after_detach() {
    let backend = FakeVipBackend::default();
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");
    adapter.attach(&authorization(3)).expect("attach epoch 3");
    adapter
        .detach(CloseReason::LeaseExpired)
        .expect("detach epoch 3");

    assert_eq!(
        adapter.attach(&authorization(2)),
        Err(AdapterError::StaleEpoch)
    );
    assert_eq!(adapter.backend().adds, 1);
}

#[test]
fn linux_vip_detach_fails_closed_on_observe_error_and_requires_read_back_absence() {
    let backend = FakeVipBackend::default();
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");
    adapter.attach(&authorization(2)).expect("attach");

    adapter.backend_mut().fail_observe = true;
    assert_eq!(
        adapter.detach(CloseReason::LeaseExpired),
        Err(AdapterError::EffectNotClosed)
    );

    adapter.backend_mut().fail_observe = false;
    adapter.backend_mut().fail_delete = true;
    assert_eq!(
        adapter.detach(CloseReason::LeaseExpired),
        Err(AdapterError::EffectNotClosed)
    );
    assert_ne!(adapter.state(), VipState::Detached);
}

#[test]
fn linux_vip_implements_effect_adapter_contract() {
    let backend = FakeVipBackend::default();
    let mut adapter =
        LinuxVipEffectAdapter::new("orders-api", "node-a", "172.30.1.100/24", "enp1s0", backend)
            .expect("adapter");

    assert!(adapter.verify_closed().is_ok());
    assert_eq!(
        adapter.open("orders-api", 2),
        Err(AdapterError::ReceiptRequired)
    );
    assert_eq!(
        adapter.open_with_receipt("orders-api", 2, [0; 32]),
        Err(AdapterError::ReceiptRequired)
    );
    assert_eq!(adapter.state(), VipState::Detached);

    adapter
        .open_with_receipt("orders-api", 2, [11; 32])
        .expect("open with receipt");
    assert_eq!(adapter.state(), VipState::Attached(2));
    assert_eq!(adapter.verify_closed(), Err(AdapterError::EffectNotClosed));

    adapter
        .close(CloseReason::LeaseExpired)
        .expect("close effect");
    assert_eq!(adapter.state(), VipState::Detached);
    assert!(adapter.verify_closed().is_ok());
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
