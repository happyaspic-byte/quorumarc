use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{
    CommitIndex, Epoch, FenceClass, Incarnation, NodeId, PolicyHash, StateRoot,
    ValidatedPromotion, WorkloadId,
};

/// Observable state of one node-local effect gate.
#[derive(Debug, Eq, PartialEq)]
pub enum GateState {
    /// No effect may leave this node.
    Closed {
        /// Highest epoch this gate has accepted.
        last_epoch: Epoch,
    },
    /// Evidence passed, but its anti-replay state is not yet durably confirmed.
    Staged {
        /// Validated in-process activation capability.
        authorization: ValidatedPromotion,
    },
    /// Evidence passed and its anti-replay state was durably confirmed.
    Prepared {
        /// Validated in-process activation capability.
        authorization: ValidatedPromotion,
    },
    /// Effect is allowed only for this holder/epoch and before expiry.
    Open {
        /// Current holder.
        holder: NodeId,
        /// Current epoch.
        epoch: Epoch,
        /// Exclusive lease expiry.
        expires_at_ms: u64,
    },
    /// Gate closed itself because a safety precondition failed.
    SelfFenced {
        /// Highest epoch this gate has accepted.
        last_epoch: Epoch,
        /// Local fail-closed reason.
        reason: SelfFenceReason,
    },
}

impl GateState {
    fn last_epoch(&self) -> Epoch {
        match self {
            Self::Closed { last_epoch } | Self::SelfFenced { last_epoch, .. } => *last_epoch,
            Self::Staged { authorization } | Self::Prepared { authorization } => {
                authorization.epoch()
            }
            Self::Open { epoch, .. } => *epoch,
        }
    }
}

/// Local reason for closing a once-prepared gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelfFenceReason {
    /// Authority lease reached its exclusive expiry.
    LeaseExpired,
    /// Operator or controller explicitly closed effects.
    ExplicitClose,
    /// A local invariant or trusted adapter failed.
    SafetyFault,
}

/// Audit material emitted when a prepared gate becomes active.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuityReceipt {
    /// Protected workload.
    pub workload: WorkloadId,
    /// Activated holder.
    pub holder: NodeId,
    /// Durable holder boot generation.
    pub incarnation: Incarnation,
    /// Activated authority epoch.
    pub epoch: Epoch,
    /// Local activation time.
    pub activated_at_ms: u64,
    /// Exclusive lease expiry.
    pub expires_at_ms: u64,
    /// Durable state position in the proof.
    pub durable_commit: CommitIndex,
    /// State root in the proof.
    pub state_root: StateRoot,
    /// Fence class accepted by the validator.
    pub fence_class: FenceClass,
    /// Pinned policy digest.
    pub policy_hash: PolicyHash,
}

/// Trusted durable state supplied when a gate process starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GateRecoveryState {
    accepted_epoch: Epoch,
    incarnation: Incarnation,
    last_observed_ms: u64,
}

impl GateRecoveryState {
    /// Constructs state read from a rollback-resistant persistence adapter.
    #[must_use]
    pub const fn new(
        accepted_epoch: Epoch,
        incarnation: Incarnation,
        last_observed_ms: u64,
    ) -> Self {
        Self {
            accepted_epoch,
            incarnation,
            last_observed_ms,
        }
    }

    /// Highest epoch durably accepted before this process started.
    #[must_use]
    pub const fn accepted_epoch(&self) -> Epoch {
        self.accepted_epoch
    }

    /// Durable boot generation allocated to this process life.
    #[must_use]
    pub const fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// Last trusted time durably observed by the previous process life.
    #[must_use]
    pub const fn last_observed_ms(&self) -> u64 {
        self.last_observed_ms
    }
}

/// Record that must be durably committed before `confirm_persisted` is called.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatePersistenceRecord {
    node: NodeId,
    workload: WorkloadId,
    policy_hash: PolicyHash,
    accepted_epoch: Epoch,
    incarnation: Incarnation,
    last_observed_ms: u64,
}

impl GatePersistenceRecord {
    /// Node whose anti-replay state must be updated.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.node
    }

    /// Workload whose anti-replay state must be updated.
    #[must_use]
    pub fn workload(&self) -> &WorkloadId {
        &self.workload
    }

    /// Policy digest associated with the accepted proof.
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Epoch that must be persisted before effects can open.
    #[must_use]
    pub const fn accepted_epoch(&self) -> Epoch {
        self.accepted_epoch
    }

    /// Candidate boot generation that must be persisted.
    #[must_use]
    pub const fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// Trusted time that must not move backward after recovery.
    #[must_use]
    pub const fn last_observed_ms(&self) -> u64 {
        self.last_observed_ms
    }
}

/// Time source trusted by the local gate enforcement boundary.
///
/// Production implementations must be monotonic, pause-aware, and compatible
/// with the lease time domain. A normal wall clock does not satisfy this trait's
/// safety contract merely because it implements the method.
pub trait TrustedClock {
    /// Returns the current time in the lease evaluation domain.
    fn now_ms(&self) -> u64;
}

/// Node-local, fail-closed external-effect gate.
pub struct EffectGate<C> {
    node: NodeId,
    workload: WorkloadId,
    policy_hash: PolicyHash,
    incarnation: Incarnation,
    clock: C,
    last_observed_ms: u64,
    state: GateState,
}

impl<C: TrustedClock> EffectGate<C> {
    /// Recovers a closed gate from trusted durable anti-replay state.
    #[must_use]
    pub fn recover(
        node: NodeId,
        workload: WorkloadId,
        policy_hash: PolicyHash,
        recovery: GateRecoveryState,
        clock: C,
    ) -> Self {
        Self {
            node,
            workload,
            policy_hash,
            incarnation: recovery.incarnation,
            clock,
            last_observed_ms: recovery.last_observed_ms,
            state: GateState::Closed {
                last_epoch: recovery.accepted_epoch,
            },
        }
    }

    /// Returns the current observable state.
    #[must_use]
    pub const fn state(&self) -> &GateState {
        &self.state
    }

    /// Stages a proof and returns the anti-replay record that must be persisted.
    pub fn stage(
        &mut self,
        authorization: ValidatedPromotion,
    ) -> Result<GatePersistenceRecord, GateError> {
        let _ = self.observe_time()?;
        if authorization.workload() != &self.workload
            || authorization.policy_hash() != self.policy_hash
        {
            return Err(GateError::GateBindingMismatch);
        }
        if authorization.candidate() != &self.node {
            return Err(GateError::WrongCandidate);
        }
        if authorization.candidate_incarnation() != self.incarnation {
            return Err(GateError::IncarnationMismatch);
        }

        match &self.state {
            GateState::Staged {
                authorization: existing,
            }
            | GateState::Prepared {
                authorization: existing,
            } if existing == &authorization => return Ok(self.persistence_record(existing)),
            GateState::Open { .. } => return Err(GateError::AlreadyOpen),
            _ => {}
        }
        if authorization.epoch() <= self.state.last_epoch() {
            return Err(GateError::StaleAuthorization);
        }
        let record = self.persistence_record(&authorization);
        self.state = GateState::Staged { authorization };
        Ok(record)
    }

    /// Confirms that the exact staged anti-replay record is durably committed.
    pub fn confirm_persisted(&mut self, record: &GatePersistenceRecord) -> Result<(), GateError> {
        let last_epoch = self.state.last_epoch();
        let staged = std::mem::replace(&mut self.state, GateState::Closed { last_epoch });
        match staged {
            GateState::Staged { authorization } => {
                if &self.persistence_record(&authorization) != record {
                    self.state = GateState::Staged { authorization };
                    return Err(GateError::PersistenceMismatch);
                }
                self.state = GateState::Prepared { authorization };
                Ok(())
            }
            other => {
                self.state = other;
                Err(GateError::NotStaged)
            }
        }
    }

    /// Opens effects for a prepared, currently active lease and emits a receipt.
    pub fn activate(&mut self) -> Result<ContinuityReceipt, GateError> {
        let now_ms = self.observe_time()?;
        let GateState::Prepared { authorization } = &self.state else {
            return Err(GateError::NotPrepared);
        };
        if now_ms < authorization.not_before_ms() {
            return Err(GateError::LeaseNotStarted);
        }
        if now_ms >= authorization.expires_at_ms() {
            let epoch = authorization.epoch();
            self.state = GateState::SelfFenced {
                last_epoch: epoch,
                reason: SelfFenceReason::LeaseExpired,
            };
            return Err(GateError::LeaseExpired);
        }

        let receipt = ContinuityReceipt {
            workload: authorization.workload().clone(),
            holder: authorization.candidate().clone(),
            incarnation: authorization.candidate_incarnation(),
            epoch: authorization.epoch(),
            activated_at_ms: now_ms,
            expires_at_ms: authorization.expires_at_ms(),
            durable_commit: authorization.durable_commit(),
            state_root: authorization.state_root(),
            fence_class: authorization.fence_class(),
            policy_hash: authorization.policy_hash(),
        };
        self.state = GateState::Open {
            holder: receipt.holder.clone(),
            epoch: receipt.epoch,
            expires_at_ms: receipt.expires_at_ms,
        };
        Ok(receipt)
    }

    /// Authorizes one effect only for the exact live holder and epoch.
    pub fn check_effect(
        &mut self,
        holder: &NodeId,
        epoch: Epoch,
    ) -> Result<(), GateError> {
        let now_ms = self.observe_time()?;
        let GateState::Open {
            holder: active_holder,
            epoch: active_epoch,
            expires_at_ms,
        } = &self.state
        else {
            return Err(GateError::GateClosed);
        };

        if now_ms >= *expires_at_ms {
            let last_epoch = *active_epoch;
            self.state = GateState::SelfFenced {
                last_epoch,
                reason: SelfFenceReason::LeaseExpired,
            };
            return Err(GateError::LeaseExpired);
        }
        if active_holder != holder {
            return Err(GateError::WrongCandidate);
        }
        if *active_epoch != epoch {
            return Err(GateError::StaleAuthorization);
        }
        Ok(())
    }

    /// Applies time passage and self-fences an expired open gate.
    pub fn tick(&mut self) -> Result<bool, GateError> {
        let now_ms = self.observe_time()?;
        let expired_epoch = match &self.state {
            GateState::Open {
                epoch,
                expires_at_ms,
                ..
            } if now_ms >= *expires_at_ms => Some(*epoch),
            _ => None,
        };
        if let Some(last_epoch) = expired_epoch {
            self.state = GateState::SelfFenced {
                last_epoch,
                reason: SelfFenceReason::LeaseExpired,
            };
            return Ok(true);
        }
        Ok(false)
    }

    /// Explicitly closes a gate while retaining anti-replay epoch memory.
    pub fn close(&mut self) {
        let last_epoch = self.state.last_epoch();
        self.state = GateState::SelfFenced {
            last_epoch,
            reason: SelfFenceReason::ExplicitClose,
        };
    }

    /// Closes a gate after a trusted local adapter reports a safety fault.
    pub fn safety_fault(&mut self) {
        let last_epoch = self.state.last_epoch();
        self.state = GateState::SelfFenced {
            last_epoch,
            reason: SelfFenceReason::SafetyFault,
        };
    }

    fn persistence_record(&self, authorization: &ValidatedPromotion) -> GatePersistenceRecord {
        GatePersistenceRecord {
            node: self.node.clone(),
            workload: self.workload.clone(),
            policy_hash: self.policy_hash,
            accepted_epoch: authorization.epoch(),
            incarnation: self.incarnation,
            last_observed_ms: self.last_observed_ms,
        }
    }

    fn observe_time(&mut self) -> Result<u64, GateError> {
        let now_ms = self.clock.now_ms();
        if now_ms < self.last_observed_ms {
            let last_epoch = self.state.last_epoch();
            self.state = GateState::SelfFenced {
                last_epoch,
                reason: SelfFenceReason::SafetyFault,
            };
            return Err(GateError::ClockRollback);
        }
        self.last_observed_ms = now_ms;
        Ok(now_ms)
    }
}

/// Typed local gate refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateError {
    /// Capability targets another workload or policy.
    GateBindingMismatch,
    /// Capability or effect targets another node.
    WrongCandidate,
    /// Capability was issued to another durable boot generation.
    IncarnationMismatch,
    /// Epoch is not newer than local anti-replay state.
    StaleAuthorization,
    /// Gate is already externally active.
    AlreadyOpen,
    /// Persistence confirmation was requested without a staged proof.
    NotStaged,
    /// Persistence confirmation does not match the staged proof.
    PersistenceMismatch,
    /// Activation was requested without preparation.
    NotPrepared,
    /// Lease activation time has not arrived.
    LeaseNotStarted,
    /// Lease reached its exclusive expiry.
    LeaseExpired,
    /// Gate is not externally active.
    GateClosed,
    /// Trusted time moved backward and the gate self-fenced.
    ClockRollback,
}

impl Display for GateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GateBindingMismatch => "authorization does not match gate binding",
            Self::WrongCandidate => "authorization targets another node",
            Self::IncarnationMismatch => "authorization targets another process incarnation",
            Self::StaleAuthorization => "authorization epoch is stale",
            Self::AlreadyOpen => "gate is already open",
            Self::NotStaged => "gate has no staged authorization",
            Self::PersistenceMismatch => "persisted anti-replay record does not match",
            Self::NotPrepared => "gate has no prepared authorization",
            Self::LeaseNotStarted => "authorization lease has not started",
            Self::LeaseExpired => "authorization lease has expired",
            Self::GateClosed => "gate is closed",
            Self::ClockRollback => "trusted gate clock moved backward",
        })
    }
}

impl Error for GateError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::{
        AuthorityState, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant,
        PromotionProof, QuorumCertificate, SafetyPolicy, StateEvidence, validate_promotion,
    };

    const NOW: u64 = 20_000;

    #[derive(Clone)]
    struct ManualClock(Arc<AtomicU64>);

    impl ManualClock {
        fn new(now_ms: u64) -> Self {
            Self(Arc::new(AtomicU64::new(now_ms)))
        }

        fn set(&self, now_ms: u64) {
            self.0.store(now_ms, Ordering::SeqCst);
        }
    }

    impl TrustedClock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    fn node(value: &str) -> NodeId {
        let Ok(identifier) = NodeId::new(value) else {
            std::process::abort();
        };
        identifier
    }

    fn workload() -> WorkloadId {
        let Ok(identifier) = WorkloadId::new("payments") else {
            std::process::abort();
        };
        identifier
    }

    fn policy_hash() -> PolicyHash {
        PolicyHash::new([3; 32])
    }

    fn authorization() -> ValidatedPromotion {
        let candidate = node("node-a");
        let epoch = Epoch(1);
        let proof = PromotionProof {
            workload: workload(),
            candidate: candidate.clone(),
            candidate_incarnation: Incarnation(1),
            epoch,
            policy_hash: policy_hash(),
            quorum: QuorumCertificate {
                epoch,
                workload: workload(),
                candidate: candidate.clone(),
                candidate_incarnation: Incarnation(1),
                policy_hash: policy_hash(),
                required_commit: CommitIndex(4),
                state_root: StateRoot::new([8; 32]),
                lease_not_before_ms: NOW,
                lease_expires_at_ms: NOW + 100,
                voters: vec![candidate.clone(), node("witness")],
            },
            fence: FenceReceipt {
                epoch,
                target: None,
                verifier: node("witness"),
                mechanism: FenceMechanism::Bootstrap,
                observed_at_ms: NOW - 5,
            },
            state: StateEvidence {
                required_commit: CommitIndex(4),
                durable_commit: CommitIndex(5),
                state_root: StateRoot::new([8; 32]),
                observed_at_ms: NOW - 5,
            },
            health: HealthAttestation {
                workload: workload(),
                node: candidate.clone(),
                incarnation: Incarnation(1),
                epoch,
                healthy: true,
                passed_checks: 2,
                observed_at_ms: NOW - 5,
            },
            lease: LeaseGrant {
                workload: workload(),
                holder: candidate,
                incarnation: Incarnation(1),
                epoch,
                not_before_ms: NOW,
                expires_at_ms: NOW + 100,
            },
        };
        let voters = BTreeSet::from([node("node-a"), node("node-b"), node("witness")]);
        let policy = SafetyPolicy::new(
            workload(),
            policy_hash(),
            [node("node-a"), node("node-b")],
            voters,
            2,
            Some(node("witness")),
            2,
            100,
            500,
            10,
            true,
        );
        let Ok(policy) = policy else {
            std::process::abort();
        };
        let result = validate_promotion(&proof, &AuthorityState::initial(), &policy, NOW);
        let Ok(authorization) = result else {
            std::process::abort();
        };
        authorization
    }

    fn gate() -> (EffectGate<ManualClock>, ManualClock) {
        let clock = ManualClock::new(NOW);
        let gate = EffectGate::recover(
            node("node-a"),
            workload(),
            policy_hash(),
            GateRecoveryState::new(Epoch(0), Incarnation(1), NOW - 10),
            clock.clone(),
        );
        (gate, clock)
    }

    fn persist_staged(gate: &mut EffectGate<ManualClock>, authorization: ValidatedPromotion) {
        let result = gate.stage(authorization);
        let Ok(record) = result else {
            std::process::abort();
        };
        if gate.confirm_persisted(&record).is_err() {
            std::process::abort();
        }
    }

    #[test]
    fn preparation_does_not_open_effects() {
        let (mut gate, _) = gate();
        assert!(gate.stage(authorization()).is_ok());
        assert_eq!(
            gate.check_effect(&node("node-a"), Epoch(1)),
            Err(GateError::GateClosed)
        );
    }

    #[test]
    fn exact_holder_and_epoch_are_required() {
        let (mut gate, _) = gate();
        persist_staged(&mut gate, authorization());
        assert!(gate.activate().is_ok());
        assert_eq!(
            gate.check_effect(&node("node-b"), Epoch(1)),
            Err(GateError::WrongCandidate)
        );
        assert_eq!(
            gate.check_effect(&node("node-a"), Epoch(0)),
            Err(GateError::StaleAuthorization)
        );
        assert!(gate.check_effect(&node("node-a"), Epoch(1)).is_ok());
    }

    #[test]
    fn expired_lease_self_fences_before_effect() {
        let (mut gate, clock) = gate();
        persist_staged(&mut gate, authorization());
        assert!(gate.activate().is_ok());
        clock.set(NOW + 100);
        assert_eq!(
            gate.check_effect(&node("node-a"), Epoch(1)),
            Err(GateError::LeaseExpired)
        );
        assert!(matches!(
            gate.state(),
            GateState::SelfFenced {
                reason: SelfFenceReason::LeaseExpired,
                ..
            }
        ));
    }

    #[test]
    fn stale_authorization_cannot_reopen_closed_gate() {
        let (mut gate, _) = gate();
        persist_staged(&mut gate, authorization());
        assert!(gate.activate().is_ok());
        gate.close();
        assert_eq!(
            gate.stage(authorization()),
            Err(GateError::StaleAuthorization)
        );
    }

    #[test]
    fn proof_from_an_old_process_incarnation_is_rejected() {
        let clock = ManualClock::new(NOW);
        let mut gate = EffectGate::recover(
            node("node-a"),
            workload(),
            policy_hash(),
            GateRecoveryState::new(Epoch(0), Incarnation(2), NOW - 10),
            clock,
        );
        assert_eq!(
            gate.stage(authorization()),
            Err(GateError::IncarnationMismatch)
        );
    }

    #[test]
    fn trusted_clock_rollback_self_fences() {
        let (mut gate, clock) = gate();
        persist_staged(&mut gate, authorization());
        assert!(gate.activate().is_ok());
        clock.set(NOW - 1);
        assert_eq!(
            gate.check_effect(&node("node-a"), Epoch(1)),
            Err(GateError::ClockRollback)
        );
        assert!(matches!(
            gate.state(),
            GateState::SelfFenced {
                reason: SelfFenceReason::SafetyFault,
                ..
            }
        ));
    }
}
