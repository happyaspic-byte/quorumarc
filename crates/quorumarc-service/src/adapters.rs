use std::collections::BTreeMap;

/// Fail-closed adapter refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterError {
    WrongTarget,
    ReadBackMismatch,
    ReceiptRequired,
    AlreadyClosed,
    UnknownOutlet,
    EffectNotClosed,
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
