use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use quorumarc_core::{
    ContinuityReceipt, EffectGate, Epoch, GateError, GatePersistenceRecord, GateState, NodeId,
    TrustedClock, ValidatedPromotion,
};

/// Defensive payload bound for the in-memory lab sink.
pub const MAX_TEST_EFFECT_SIZE: usize = 65_536;

/// One externally observable record captured by the lab-only sink.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestEffectRecord {
    operation_id: [u8; 16],
    holder: NodeId,
    epoch: Epoch,
    payload: Vec<u8>,
}

impl TestEffectRecord {
    /// Stable operation identity used for idempotent retries.
    #[must_use]
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Exact holder admitted by the core effect gate.
    #[must_use]
    pub const fn holder(&self) -> &NodeId {
        &self.holder
    }

    /// Exact authority epoch admitted by the core effect gate.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Opaque lab payload captured as the simulated external effect.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Successful test-sink transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectOutcome {
    /// New effect was captured after a live gate check.
    Recorded,
    /// Exact operation retry was already captured and the gate remains live.
    AlreadyRecorded,
}

/// Stable test-effect decision code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectReasonCode {
    /// Operation ID used the zero sentinel.
    ZeroOperationId,
    /// Payload exceeded the test sink's defensive limit.
    PayloadTooLarge,
    /// Operation ID was reused for another effect and the gate self-fenced.
    OperationIdConflict,
    /// Gate binding did not match this workload or policy.
    GateBindingMismatch,
    /// Holder did not match the active node.
    WrongHolder,
    /// Incarnation did not match during preparation.
    IncarnationMismatch,
    /// Epoch was stale or did not match the open gate.
    StaleEpoch,
    /// Gate was already open during preparation.
    AlreadyOpen,
    /// Durable confirmation was attempted without a staged proof.
    NotStaged,
    /// Durable confirmation differed from the staged proof.
    PersistenceMismatch,
    /// Activation was attempted before preparation.
    NotPrepared,
    /// Lease activation time had not arrived.
    LeaseNotStarted,
    /// Lease reached its exclusive expiry.
    LeaseExpired,
    /// Gate was closed or self-fenced.
    GateClosed,
    /// Trusted time moved backward.
    ClockRollback,
}

impl EffectReasonCode {
    /// Stable machine-readable log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ZeroOperationId => "EFFECT_REFUSED_ZERO_OPERATION_ID",
            Self::PayloadTooLarge => "EFFECT_REFUSED_PAYLOAD_TOO_LARGE",
            Self::OperationIdConflict => "EFFECT_REFUSED_OPERATION_ID_CONFLICT",
            Self::GateBindingMismatch => "EFFECT_REFUSED_GATE_BINDING_MISMATCH",
            Self::WrongHolder => "EFFECT_REFUSED_WRONG_HOLDER",
            Self::IncarnationMismatch => "EFFECT_REFUSED_INCARNATION_MISMATCH",
            Self::StaleEpoch => "EFFECT_REFUSED_STALE_EPOCH",
            Self::AlreadyOpen => "EFFECT_REFUSED_ALREADY_OPEN",
            Self::NotStaged => "EFFECT_REFUSED_NOT_STAGED",
            Self::PersistenceMismatch => "EFFECT_REFUSED_PERSISTENCE_MISMATCH",
            Self::NotPrepared => "EFFECT_REFUSED_NOT_PREPARED",
            Self::LeaseNotStarted => "EFFECT_REFUSED_LEASE_NOT_STARTED",
            Self::LeaseExpired => "EFFECT_REFUSED_LEASE_EXPIRED",
            Self::GateClosed => "EFFECT_REFUSED_GATE_CLOSED",
            Self::ClockRollback => "EFFECT_REFUSED_CLOCK_ROLLBACK",
        }
    }
}

/// Fail-closed test-effect error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectEmitError {
    /// Operation ID used the all-zero sentinel.
    ZeroOperationId,
    /// Payload exceeded the in-memory sink's defensive limit.
    PayloadTooLarge {
        /// Supplied payload bytes.
        actual: usize,
        /// Maximum admitted bytes.
        maximum: usize,
    },
    /// Same operation identity was reused with different content or authority.
    OperationIdConflict,
    /// Core gate refused the operation.
    Gate(GateError),
}

impl EffectEmitError {
    /// Stable reason code for structured test traces.
    #[must_use]
    pub const fn reason_code(self) -> EffectReasonCode {
        match self {
            Self::ZeroOperationId => EffectReasonCode::ZeroOperationId,
            Self::PayloadTooLarge { .. } => EffectReasonCode::PayloadTooLarge,
            Self::OperationIdConflict => EffectReasonCode::OperationIdConflict,
            Self::Gate(error) => match error {
                GateError::GateBindingMismatch => EffectReasonCode::GateBindingMismatch,
                GateError::WrongCandidate => EffectReasonCode::WrongHolder,
                GateError::IncarnationMismatch => EffectReasonCode::IncarnationMismatch,
                GateError::StaleAuthorization => EffectReasonCode::StaleEpoch,
                GateError::AlreadyOpen => EffectReasonCode::AlreadyOpen,
                GateError::NotStaged => EffectReasonCode::NotStaged,
                GateError::PersistenceMismatch => EffectReasonCode::PersistenceMismatch,
                GateError::NotPrepared => EffectReasonCode::NotPrepared,
                GateError::LeaseNotStarted => EffectReasonCode::LeaseNotStarted,
                GateError::LeaseExpired => EffectReasonCode::LeaseExpired,
                GateError::GateClosed => EffectReasonCode::GateClosed,
                GateError::ClockRollback => EffectReasonCode::ClockRollback,
            },
        }
    }
}

impl Display for EffectEmitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroOperationId => formatter.write_str("effect operation ID is zero"),
            Self::PayloadTooLarge { actual, maximum } => write!(
                formatter,
                "test effect payload {actual} exceeds maximum {maximum}"
            ),
            Self::OperationIdConflict => {
                formatter.write_str("effect operation ID was reused for another request")
            }
            Self::Gate(error) => write!(formatter, "core effect gate refused output: {error}"),
        }
    }
}

impl Error for EffectEmitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Gate(error) => Some(error),
            _ => None,
        }
    }
}

/// Lab-only sink that owns the core gate and cannot write around it.
///
/// Every new effect and exact retry calls `EffectGate::check_effect`
/// immediately before its result is observed. The exclusive `&mut self`
/// boundary prevents another caller from changing the gate between the check
/// and in-memory capture. This does not claim nftables, eBPF, storage, VIP, or
/// hardware fencing enforcement.
pub struct TestEffectActor<C> {
    gate: EffectGate<C>,
    records: BTreeMap<[u8; 16], TestEffectRecord>,
}

impl<C: TrustedClock> TestEffectActor<C> {
    /// Wraps an existing fail-closed core gate with an empty test sink.
    #[must_use]
    pub fn new(gate: EffectGate<C>) -> Self {
        Self {
            gate,
            records: BTreeMap::new(),
        }
    }

    /// Observable core gate state.
    #[must_use]
    pub const fn gate_state(&self) -> &GateState {
        self.gate.state()
    }

    /// Stages a core-validated promotion without opening the sink.
    pub fn stage(
        &mut self,
        authorization: ValidatedPromotion,
    ) -> Result<GatePersistenceRecord, GateError> {
        self.gate.stage(authorization)
    }

    /// Confirms the exact anti-replay record after external durability.
    pub fn confirm_persisted(&mut self, record: &GatePersistenceRecord) -> Result<(), GateError> {
        self.gate.confirm_persisted(record)
    }

    /// Activates the prepared core gate and returns its audit receipt.
    pub fn activate(&mut self) -> Result<ContinuityReceipt, GateError> {
        self.gate.activate()
    }

    /// Captures one simulated external effect after an exact live gate check.
    pub fn emit(
        &mut self,
        operation_id: [u8; 16],
        holder: NodeId,
        epoch: Epoch,
        payload: &[u8],
    ) -> Result<EffectOutcome, EffectEmitError> {
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(EffectEmitError::ZeroOperationId);
        }
        if payload.len() > MAX_TEST_EFFECT_SIZE {
            return Err(EffectEmitError::PayloadTooLarge {
                actual: payload.len(),
                maximum: MAX_TEST_EFFECT_SIZE,
            });
        }

        if let Some(existing) = self.records.get(&operation_id) {
            if existing.holder != holder || existing.epoch != epoch || existing.payload != payload {
                self.gate.safety_fault();
                return Err(EffectEmitError::OperationIdConflict);
            }
            self.gate
                .check_effect(&holder, epoch)
                .map_err(EffectEmitError::Gate)?;
            return Ok(EffectOutcome::AlreadyRecorded);
        }

        self.gate
            .check_effect(&holder, epoch)
            .map_err(EffectEmitError::Gate)?;
        self.records.insert(
            operation_id,
            TestEffectRecord {
                operation_id,
                holder,
                epoch,
                payload: payload.to_vec(),
            },
        );
        Ok(EffectOutcome::Recorded)
    }

    /// Applies lease passage to the core gate.
    pub fn tick(&mut self) -> Result<bool, GateError> {
        self.gate.tick()
    }

    /// Explicitly closes the core gate.
    pub fn close(&mut self) {
        self.gate.close();
    }

    /// Captured lab effects in deterministic operation-ID order.
    #[must_use]
    pub fn records(&self) -> impl ExactSizeIterator<Item = &TestEffectRecord> {
        self.records.values()
    }
}
