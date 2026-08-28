use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

const FENCE_RECEIPT_DOMAIN: &[u8] = b"quorumarc/fence-receipt/v1\0";

/// Fail-closed adapter refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    WrongTarget,
    ReadBackMismatch,
    ReceiptRequired,
    AlreadyClosed,
    UnknownOutlet,
    EffectNotClosed,
    StaleEpoch,
}

/// Observed power state of one mapped outlet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodePowerState {
    On,
    Off,
}

/// Why an EffectAdapter closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    LeaseExpired,
    ExplicitClose,
}

/// Fence command against a mapped target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FenceRequest<'a> {
    pub target: &'a str,
    pub expected_outlet: &'a str,
    pub challenge: [u8; 16],
}

/// Evidence returned by a fence command. It is not itself a receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceEvidence {
    pub target: String,
    pub outlet: String,
    pub challenge: [u8; 16],
}

/// Authoritative receipt certifying that a host cannot emit effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedFenceReceipt {
    target: String,
    outlet: String,
    challenge: [u8; 16],
    digest: [u8; 32],
    signature: [u8; 64],
}

impl SignedFenceReceipt {
    pub(crate) fn from_parts(
        target: String,
        outlet: String,
        challenge: [u8; 16],
        digest: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            target,
            outlet,
            challenge,
            digest,
            signature,
        }
    }

    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }

    #[must_use]
    pub fn outlet(&self) -> &str {
        &self.outlet
    }

    #[must_use]
    pub const fn challenge(&self) -> [u8; 16] {
        self.challenge
    }

    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn signature(&self) -> [u8; 64] {
        self.signature
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), AdapterError> {
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.digest, &signature)
            .map_err(|_error| AdapterError::ReceiptRequired)
    }
}

/// Authoritative fencing adapter.
pub trait FenceAdapter {
    fn fence(&mut self, request: FenceRequest<'_>) -> Result<FenceEvidence, AdapterError>;
    fn verify(&mut self, evidence: &FenceEvidence) -> Result<(), AdapterError>;
}

/// External-effect adapter. Closed is the only safe default.
pub trait EffectAdapter {
    fn verify_closed(&self) -> Result<(), AdapterError>;
    fn open(&mut self, workload: &str, epoch: u64) -> Result<(), AdapterError>;
    fn open_with_receipt(
        &mut self,
        workload: &str,
        epoch: u64,
        receipt_digest: [u8; 32],
    ) -> Result<(), AdapterError>;
    fn close(&mut self, reason: CloseReason) -> Result<(), AdapterError>;
}

/// Deterministic PDU mock with independent command and read-back maps.
#[derive(Clone, Debug)]
pub struct MockPduFence {
    mapping: BTreeMap<String, String>,
    command_state: BTreeMap<String, NodePowerState>,
    read_back: BTreeMap<String, NodePowerState>,
}

impl MockPduFence {
    /// Creates a fixed target-to-outlet map.
    #[must_use]
    pub fn new(mapping: impl IntoIterator<Item = (&'static str, &'static str)>) -> Self {
        let mapping = mapping
            .into_iter()
            .map(|(target, outlet)| (target.to_owned(), outlet.to_owned()))
            .collect();
        Self {
            mapping,
            command_state: BTreeMap::new(),
            read_back: BTreeMap::new(),
        }
    }

    /// Sets commanded power without changing independent read-back.
    pub fn set_power(&mut self, outlet: &str, state: NodePowerState) {
        self.command_state.insert(outlet.to_owned(), state);
    }

    /// Sets the independent read-back observation.
    pub fn set_read_back(&mut self, outlet: &str, state: NodePowerState) {
        self.read_back.insert(outlet.to_owned(), state);
    }

    /// Issues a receipt only after independent Off read-back.
    pub fn signed_receipt(
        &mut self,
        evidence: &FenceEvidence,
        signing_key: &SigningKey,
    ) -> Result<SignedFenceReceipt, AdapterError> {
        self.verify(evidence)?;
        let digest = fence_receipt_digest(evidence);
        let signature = signing_key.sign(&digest).to_bytes();
        Ok(SignedFenceReceipt {
            target: evidence.target.clone(),
            outlet: evidence.outlet.clone(),
            challenge: evidence.challenge,
            digest,
            signature,
        })
    }
}

fn fence_receipt_digest(evidence: &FenceEvidence) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FENCE_RECEIPT_DOMAIN);
    hasher.update(evidence.target.as_bytes());
    hasher.update([0]);
    hasher.update(evidence.outlet.as_bytes());
    hasher.update([0]);
    hasher.update(evidence.challenge);
    hasher.finalize().into()
}

impl FenceAdapter for MockPduFence {
    fn fence(&mut self, request: FenceRequest<'_>) -> Result<FenceEvidence, AdapterError> {
        let mapped = self
            .mapping
            .get(request.target)
            .ok_or(AdapterError::WrongTarget)?;
        if mapped != request.expected_outlet {
            return Err(AdapterError::WrongTarget);
        }
        self.command_state
            .insert(mapped.clone(), NodePowerState::Off);
        Ok(FenceEvidence {
            target: request.target.to_owned(),
            outlet: mapped.clone(),
            challenge: request.challenge,
        })
    }

    fn verify(&mut self, evidence: &FenceEvidence) -> Result<(), AdapterError> {
        let mapped = self
            .mapping
            .get(&evidence.target)
            .ok_or(AdapterError::WrongTarget)?;
        if mapped != &evidence.outlet {
            return Err(AdapterError::WrongTarget);
        }
        match self.read_back.get(&evidence.outlet) {
            Some(NodePowerState::Off) => Ok(()),
            Some(NodePowerState::On) => Err(AdapterError::ReadBackMismatch),
            None => Err(AdapterError::UnknownOutlet),
        }
    }
}

/// In-memory EffectGate adapter that never opens without a receipt digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockEffectAdapter {
    closed: bool,
    open_epoch: Option<(String, u64, [u8; 32])>,
}

impl MockEffectAdapter {
    /// Starts closed with no receipt.
    #[must_use]
    pub const fn closed() -> Self {
        Self {
            closed: true,
            open_epoch: None,
        }
    }
}

impl EffectAdapter for MockEffectAdapter {
    fn verify_closed(&self) -> Result<(), AdapterError> {
        if self.closed && self.open_epoch.is_none() {
            Ok(())
        } else {
            Err(AdapterError::EffectNotClosed)
        }
    }

    fn open(&mut self, _workload: &str, _epoch: u64) -> Result<(), AdapterError> {
        Err(AdapterError::ReceiptRequired)
    }

    fn open_with_receipt(
        &mut self,
        workload: &str,
        epoch: u64,
        receipt_digest: [u8; 32],
    ) -> Result<(), AdapterError> {
        if receipt_digest.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::ReceiptRequired);
        }
        self.closed = false;
        self.open_epoch = Some((workload.to_owned(), epoch, receipt_digest));
        Ok(())
    }

    fn close(&mut self, _reason: CloseReason) -> Result<(), AdapterError> {
        self.closed = true;
        self.open_epoch = None;
        Ok(())
    }
}

/// Production default: effects stay closed regardless of receipts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClosedOnlyEffectAdapter;

impl EffectAdapter for ClosedOnlyEffectAdapter {
    fn verify_closed(&self) -> Result<(), AdapterError> {
        Ok(())
    }

    fn open(&mut self, _workload: &str, _epoch: u64) -> Result<(), AdapterError> {
        Err(AdapterError::ReceiptRequired)
    }

    fn open_with_receipt(
        &mut self,
        _workload: &str,
        _epoch: u64,
        _receipt_digest: [u8; 32],
    ) -> Result<(), AdapterError> {
        Err(AdapterError::ReceiptRequired)
    }

    fn close(&mut self, _reason: CloseReason) -> Result<(), AdapterError> {
        Ok(())
    }
}

/// Observable VIP ownership state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VipState {
    Detached,
    Attached(u64),
}

/// Receipt-gated VIP ownership model used before rtnetlink integration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VipAdapter {
    address: String,
    interface: String,
    state: VipState,
}

impl VipAdapter {
    #[must_use]
    pub fn new(address: impl Into<String>, interface: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            interface: interface.into(),
            state: VipState::Detached,
        }
    }

    #[must_use]
    pub const fn state(&self) -> VipState {
        self.state
    }

    pub fn attach(&mut self, epoch: u64, receipt_digest: [u8; 32]) -> Result<(), AdapterError> {
        if epoch == 0 || receipt_digest.iter().all(|byte| *byte == 0) {
            return Err(AdapterError::ReceiptRequired);
        }
        self.state = VipState::Attached(epoch);
        Ok(())
    }

    pub fn detach(&mut self, _reason: CloseReason) -> Result<(), AdapterError> {
        self.state = VipState::Detached;
        Ok(())
    }
}

/// Workload readiness observed through the service manager.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkloadHealth {
    Stopped,
    Healthy,
}

/// Fail-closed named systemd workload model used before D-Bus integration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemdWorkloadAdapter {
    unit: String,
    service_running: bool,
    active_epoch: Option<u64>,
}

impl SystemdWorkloadAdapter {
    #[must_use]
    pub fn new(unit: impl Into<String>) -> Self {
        Self {
            unit: unit.into(),
            service_running: false,
            active_epoch: None,
        }
    }

    pub fn set_service_running(&mut self, running: bool) {
        self.service_running = running;
        if !running {
            self.active_epoch = None;
        }
    }

    #[must_use]
    pub const fn health(&self) -> WorkloadHealth {
        if self.service_running {
            WorkloadHealth::Healthy
        } else {
            WorkloadHealth::Stopped
        }
    }

    pub fn activate(&mut self, epoch: u64) -> Result<(), AdapterError> {
        if !self.service_running || epoch == 0 {
            return Err(AdapterError::EffectNotClosed);
        }
        self.active_epoch = Some(epoch);
        Ok(())
    }

    pub fn drain(&mut self) -> Result<(), AdapterError> {
        self.active_epoch = None;
        Ok(())
    }

    #[must_use]
    pub const fn active_epoch(&self) -> Option<u64> {
        self.active_epoch
    }
}
