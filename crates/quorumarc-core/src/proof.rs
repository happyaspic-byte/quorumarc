use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{CommitIndex, Epoch, Incarnation, NodeId, PolicyHash, StateRoot, WorkloadId};

/// The authority accepted before evaluating a new proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityState {
    /// Highest accepted authority epoch.
    pub epoch: Epoch,
    /// Previously active node, or `None` during first bootstrap.
    pub holder: Option<NodeId>,
    /// Previously certified lease expiry in the trusted evaluation time domain.
    pub lease_expires_at_ms: Option<u64>,
}

impl AuthorityState {
    /// The initial state before any node has held authority.
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            epoch: Epoch(0),
            holder: None,
            lease_expires_at_ms: None,
        }
    }
}

/// Votes bound to one promotion epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    /// Promotion epoch covered by these votes.
    pub epoch: Epoch,
    /// Workload bound by the voter decision.
    pub workload: WorkloadId,
    /// Candidate bound by the voter decision.
    pub candidate: NodeId,
    /// Candidate boot generation bound by the voter decision.
    pub candidate_incarnation: Incarnation,
    /// Policy digest bound by the voter decision.
    pub policy_hash: PolicyHash,
    /// Minimum state position bound by the voter decision.
    pub required_commit: CommitIndex,
    /// Expected state digest bound by the voter decision.
    pub state_root: StateRoot,
    /// Lease start bound by the voter decision.
    pub lease_not_before_ms: u64,
    /// Lease expiry bound by the voter decision.
    pub lease_expires_at_ms: u64,
    /// Voter identities. Duplicates are rejected rather than silently removed.
    pub voters: Vec<NodeId>,
}

/// Fencing mechanism reported by a fence verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FenceMechanism {
    /// First activation only, when no previous authority exists.
    Bootstrap,
    /// Previous host was powered off by a hardware controller.
    HardwarePower,
    /// Previous host lost exclusive storage authority.
    StorageReservation,
    /// A separately enforced EffectGate lease expired plus the policy guard.
    EffectGateExpired,
    /// Operationally useful but too weak to authorize automatic promotion.
    GracefulShutdown,
}

/// Stable fence class copied into an activation receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceClass {
    /// Initial activation without a previous holder.
    Bootstrap,
    /// Hardware power fencing.
    HardwarePower,
    /// Exclusive storage fencing.
    StorageReservation,
    /// Independently enforced gate expiry.
    EffectGateExpiry,
}

/// Evidence that the previous authority can no longer create effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceReceipt {
    /// New epoch for which the fence was verified.
    pub epoch: Epoch,
    /// Fenced previous holder; absent only for bootstrap.
    pub target: Option<NodeId>,
    /// Configured voter that verified the fence.
    pub verifier: NodeId,
    /// Fence mechanism and mechanism-specific evidence.
    pub mechanism: FenceMechanism,
    /// Monotonic-time sample in the verifier's model domain.
    pub observed_at_ms: u64,
}

/// Candidate durable-state evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateEvidence {
    /// Commit index required by the consensus promotion record.
    pub required_commit: CommitIndex,
    /// Commit index durably present on the candidate.
    pub durable_commit: CommitIndex,
    /// Voter-bound digest of the required committed state.
    pub state_root: StateRoot,
    /// Monotonic-time sample in the proof evaluation domain.
    pub observed_at_ms: u64,
}

/// Workload-specific readiness evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthAttestation {
    /// Protected workload checked by the adapter.
    pub workload: WorkloadId,
    /// Candidate checked by the adapter.
    pub node: NodeId,
    /// Candidate boot generation that was checked.
    pub incarnation: Incarnation,
    /// Promotion epoch covered by this check.
    pub epoch: Epoch,
    /// Aggregate readiness result.
    pub healthy: bool,
    /// Number of policy-required checks that passed.
    pub passed_checks: u16,
    /// Monotonic-time sample in the proof evaluation domain.
    pub observed_at_ms: u64,
}

/// Bounded authority grant checked at every effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    /// Protected workload.
    pub workload: WorkloadId,
    /// Authorized node.
    pub holder: NodeId,
    /// Candidate boot generation covered by this lease.
    pub incarnation: Incarnation,
    /// Authorized epoch.
    pub epoch: Epoch,
    /// Earliest safe activation time.
    pub not_before_ms: u64,
    /// Exclusive upper bound for authority.
    pub expires_at_ms: u64,
}

/// Complete evidence required before local effect preparation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionProof {
    /// Protected workload.
    pub workload: WorkloadId,
    /// Proposed authority holder.
    pub candidate: NodeId,
    /// Durable candidate boot generation.
    pub candidate_incarnation: Incarnation,
    /// Proposed authority generation.
    pub epoch: Epoch,
    /// Digest of the exact policy used to create the proof.
    pub policy_hash: PolicyHash,
    /// Consensus voter evidence.
    pub quorum: QuorumCertificate,
    /// Old-authority exclusion evidence.
    pub fence: FenceReceipt,
    /// Recoverable candidate-state evidence.
    pub state: StateEvidence,
    /// Workload readiness evidence.
    pub health: HealthAttestation,
    /// Bounded authority interval.
    pub lease: LeaseGrant,
}

/// Validated, immutable Gate 0 policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafetyPolicy {
    workload: WorkloadId,
    policy_hash: PolicyHash,
    candidates: BTreeSet<NodeId>,
    voters: BTreeSet<NodeId>,
    quorum_size: usize,
    required_witness: Option<NodeId>,
    min_health_checks: u16,
    max_evidence_age_ms: u64,
    max_lease_duration_ms: u64,
    lease_guard_ms: u64,
    allow_gate_expiry_fence: bool,
}

impl SafetyPolicy {
    /// Constructs a policy after validating its quorum and timing bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workload: WorkloadId,
        policy_hash: PolicyHash,
        candidates: impl IntoIterator<Item = NodeId>,
        voters: impl IntoIterator<Item = NodeId>,
        quorum_size: usize,
        required_witness: Option<NodeId>,
        min_health_checks: u16,
        max_evidence_age_ms: u64,
        max_lease_duration_ms: u64,
        lease_guard_ms: u64,
        allow_gate_expiry_fence: bool,
    ) -> Result<Self, PolicyError> {
        let candidates = candidates.into_iter().collect::<BTreeSet<_>>();
        let voters = voters.into_iter().collect::<BTreeSet<_>>();
        if candidates.is_empty() {
            return Err(PolicyError::NoCandidates);
        }
        if voters.is_empty() {
            return Err(PolicyError::NoVoters);
        }
        if !candidates.is_subset(&voters) {
            return Err(PolicyError::CandidateNotVoter);
        }
        if quorum_size == 0 || quorum_size > voters.len() {
            return Err(PolicyError::InvalidQuorumSize);
        }
        if quorum_size <= voters.len() / 2 {
            return Err(PolicyError::NonIntersectingQuorum);
        }
        if required_witness
            .as_ref()
            .is_some_and(|witness| !voters.contains(witness))
        {
            return Err(PolicyError::WitnessNotConfigured);
        }
        if required_witness
            .as_ref()
            .is_some_and(|witness| candidates.contains(witness))
        {
            return Err(PolicyError::WitnessIsCandidate);
        }
        if min_health_checks == 0 {
            return Err(PolicyError::ZeroHealthChecks);
        }
        if max_evidence_age_ms == 0 || max_lease_duration_ms == 0 {
            return Err(PolicyError::ZeroTimeBound);
        }

        Ok(Self {
            workload,
            policy_hash,
            candidates,
            voters,
            quorum_size,
            required_witness,
            min_health_checks,
            max_evidence_age_ms,
            max_lease_duration_ms,
            lease_guard_ms,
            allow_gate_expiry_fence,
        })
    }

    /// Workload pinned by this policy.
    #[must_use]
    pub fn workload(&self) -> &WorkloadId {
        &self.workload
    }

    /// Digest pinned by this policy.
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }
}

/// Invalid policy construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// No nodes were eligible to host the protected workload.
    NoCandidates,
    /// No voter identities were supplied.
    NoVoters,
    /// An eligible candidate was absent from the voter set.
    CandidateNotVoter,
    /// Quorum size was zero or larger than the voter set.
    InvalidQuorumSize,
    /// Quorum size did not guarantee pairwise voter-set intersection.
    NonIntersectingQuorum,
    /// Required witness was absent from the configured voter set.
    WitnessNotConfigured,
    /// Required witness was incorrectly allowed to host the workload.
    WitnessIsCandidate,
    /// Policy did not require any workload health check.
    ZeroHealthChecks,
    /// An evidence or lease duration bound was zero.
    ZeroTimeBound,
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidates => formatter.write_str("policy has no workload candidates"),
            Self::NoVoters => formatter.write_str("policy has no voters"),
            Self::CandidateNotVoter => {
                formatter.write_str("a workload candidate is not a configured voter")
            }
            Self::InvalidQuorumSize => formatter.write_str("policy quorum size is invalid"),
            Self::NonIntersectingQuorum => {
                formatter.write_str("policy quorum sets do not necessarily intersect")
            }
            Self::WitnessNotConfigured => {
                formatter.write_str("required witness is not a configured voter")
            }
            Self::WitnessIsCandidate => {
                formatter.write_str("required witness cannot be a workload candidate")
            }
            Self::ZeroHealthChecks => {
                formatter.write_str("policy must require at least one health check")
            }
            Self::ZeroTimeBound => formatter.write_str("policy time bound must be non-zero"),
        }
    }
}

impl Error for PolicyError {}

/// Capability produced only after all Gate 0 checks pass.
#[derive(Debug, Eq, PartialEq)]
pub struct ValidatedPromotion {
    workload: WorkloadId,
    candidate: NodeId,
    candidate_incarnation: Incarnation,
    epoch: Epoch,
    policy_hash: PolicyHash,
    not_before_ms: u64,
    expires_at_ms: u64,
    durable_commit: CommitIndex,
    state_root: StateRoot,
    fence_class: FenceClass,
}

impl ValidatedPromotion {
    /// Workload this capability can activate.
    #[must_use]
    pub fn workload(&self) -> &WorkloadId {
        &self.workload
    }

    /// Node this capability can activate.
    #[must_use]
    pub fn candidate(&self) -> &NodeId {
        &self.candidate
    }

    /// Durable boot generation authorised by this proof.
    #[must_use]
    pub const fn candidate_incarnation(&self) -> Incarnation {
        self.candidate_incarnation
    }

    /// Monotonic authority epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Earliest activation time.
    #[must_use]
    pub const fn not_before_ms(&self) -> u64 {
        self.not_before_ms
    }

    /// Exclusive authority expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Candidate durable commit included in the proof.
    #[must_use]
    pub const fn durable_commit(&self) -> CommitIndex {
        self.durable_commit
    }

    /// Candidate state root included in the proof.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    /// Validated fence class.
    #[must_use]
    pub const fn fence_class(&self) -> FenceClass {
        self.fence_class
    }

    /// Pinned policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }
}

/// Typed refusal reason. Every variant leaves the EffectGate closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofError {
    /// Proof workload differs from policy workload.
    WorkloadMismatch,
    /// Proof policy digest differs from the pinned policy.
    PolicyHashMismatch,
    /// Proposed epoch is not greater than the accepted epoch.
    StaleEpoch,
    /// A component was signed or attested for another epoch.
    EpochMismatch,
    /// Quorum certificate does not bind the complete promotion subject.
    QuorumBindingMismatch,
    /// Candidate is not a configured voter.
    CandidateNotConfigured,
    /// Candidate already holds the current promotion authority.
    CandidateAlreadyHoldsAuthority,
    /// Candidate is absent from the voter certificate.
    CandidateDidNotVote,
    /// A configured quorum was not reached.
    InsufficientQuorum,
    /// Voter certificate contains a duplicate identity.
    DuplicateVoter,
    /// Voter certificate includes an unknown identity.
    UnknownVoter,
    /// Required independent witness is absent.
    MissingWitness,
    /// Fence verifier is not both configured and part of this quorum.
    InvalidFenceVerifier,
    /// Bootstrap fencing was used after authority already existed.
    BootstrapNotAllowed,
    /// First activation did not carry a clean bootstrap receipt.
    InvalidBootstrap,
    /// Fence target differs from the prior holder.
    WrongFenceTarget,
    /// Fence mechanism cannot prove exclusion.
    WeakFence,
    /// Gate-expiry fencing is disabled by policy.
    GateExpiryFenceDisabled,
    /// Lease guard has not elapsed after the old gate's worst-case expiry.
    FenceGuardNotElapsed,
    /// Evidence timestamp lies in the evaluator's future.
    EvidenceFromFuture,
    /// Evidence is older than policy permits.
    EvidenceTooOld,
    /// Candidate durable commit is behind the required commit.
    CandidateStateBehind,
    /// Candidate supplied the sentinel empty state root.
    EmptyStateRoot,
    /// Health evidence targets another node or workload.
    HealthSubjectMismatch,
    /// Candidate health evidence did not pass.
    CandidateUnhealthy,
    /// Fewer policy-required health checks passed than required.
    InsufficientHealthChecks,
    /// Lease targets another node or workload.
    LeaseSubjectMismatch,
    /// Lease bounds are reversed or equal.
    InvalidLeaseInterval,
    /// Lease is longer than the policy maximum.
    LeaseTooLong,
    /// Lease is not active at proof evaluation time.
    LeaseNotActive,
    /// Lease starts before verified exclusion is safe.
    LeaseStartsBeforeFence,
}

impl Display for ProofError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WorkloadMismatch => "proof workload does not match policy",
            Self::PolicyHashMismatch => "proof policy hash does not match policy",
            Self::StaleEpoch => "proof epoch is stale",
            Self::EpochMismatch => "proof component epoch does not match",
            Self::QuorumBindingMismatch => "quorum certificate binding does not match proof",
            Self::CandidateNotConfigured => "candidate is not configured",
            Self::CandidateAlreadyHoldsAuthority => "candidate already holds current authority",
            Self::CandidateDidNotVote => "candidate is absent from quorum certificate",
            Self::InsufficientQuorum => "quorum certificate is too small",
            Self::DuplicateVoter => "quorum certificate contains duplicate voter",
            Self::UnknownVoter => "quorum certificate contains unknown voter",
            Self::MissingWitness => "required witness is absent",
            Self::InvalidFenceVerifier => "fence verifier is not authorised",
            Self::BootstrapNotAllowed => "bootstrap fence is not allowed",
            Self::InvalidBootstrap => "bootstrap fence receipt is invalid",
            Self::WrongFenceTarget => "fence target does not match prior authority",
            Self::WeakFence => "fence mechanism is not authoritative",
            Self::GateExpiryFenceDisabled => "gate-expiry fencing is disabled",
            Self::FenceGuardNotElapsed => "fence expiry guard has not elapsed",
            Self::EvidenceFromFuture => "evidence timestamp is in the future",
            Self::EvidenceTooOld => "evidence is too old",
            Self::CandidateStateBehind => "candidate durable state is behind",
            Self::EmptyStateRoot => "state root is empty",
            Self::HealthSubjectMismatch => "health attestation subject does not match",
            Self::CandidateUnhealthy => "candidate is unhealthy",
            Self::InsufficientHealthChecks => "too few policy health checks passed",
            Self::LeaseSubjectMismatch => "lease subject does not match",
            Self::InvalidLeaseInterval => "lease interval is invalid",
            Self::LeaseTooLong => "lease duration exceeds policy",
            Self::LeaseNotActive => "lease is not active",
            Self::LeaseStartsBeforeFence => "lease starts before fence is safe",
        })
    }
}

impl Error for ProofError {}

/// Validates every Gate 0 proof component and returns an activation capability.
pub fn validate_promotion(
    proof: &PromotionProof,
    current: &AuthorityState,
    policy: &SafetyPolicy,
    now_ms: u64,
) -> Result<ValidatedPromotion, ProofError> {
    if proof.workload != policy.workload {
        return Err(ProofError::WorkloadMismatch);
    }
    if proof.policy_hash != policy.policy_hash {
        return Err(ProofError::PolicyHashMismatch);
    }
    if proof.epoch <= current.epoch {
        return Err(ProofError::StaleEpoch);
    }
    if !policy.candidates.contains(&proof.candidate) {
        return Err(ProofError::CandidateNotConfigured);
    }
    if current.holder.as_ref() == Some(&proof.candidate) {
        return Err(ProofError::CandidateAlreadyHoldsAuthority);
    }
    if proof.quorum.epoch != proof.epoch
        || proof.fence.epoch != proof.epoch
        || proof.health.epoch != proof.epoch
        || proof.lease.epoch != proof.epoch
    {
        return Err(ProofError::EpochMismatch);
    }
    if proof.quorum.workload != proof.workload
        || proof.quorum.candidate != proof.candidate
        || proof.quorum.candidate_incarnation != proof.candidate_incarnation
        || proof.quorum.policy_hash != proof.policy_hash
        || proof.quorum.required_commit != proof.state.required_commit
        || proof.quorum.state_root != proof.state.state_root
        || proof.quorum.lease_not_before_ms != proof.lease.not_before_ms
        || proof.quorum.lease_expires_at_ms != proof.lease.expires_at_ms
    {
        return Err(ProofError::QuorumBindingMismatch);
    }

    let quorum = validate_quorum(proof, policy)?;
    let (fence_class, safe_not_before_ms) =
        validate_fence(proof, current, policy, &quorum, now_ms)?;
    validate_fresh(proof.state.observed_at_ms, now_ms, policy.max_evidence_age_ms)?;
    if proof.state.durable_commit < proof.state.required_commit {
        return Err(ProofError::CandidateStateBehind);
    }
    if proof.state.state_root.is_zero() {
        return Err(ProofError::EmptyStateRoot);
    }
    validate_health(proof, policy, now_ms)?;
    validate_lease(proof, policy, safe_not_before_ms, now_ms)?;

    Ok(ValidatedPromotion {
        workload: proof.workload.clone(),
        candidate: proof.candidate.clone(),
        candidate_incarnation: proof.candidate_incarnation,
        epoch: proof.epoch,
        policy_hash: proof.policy_hash,
        not_before_ms: proof.lease.not_before_ms,
        expires_at_ms: proof.lease.expires_at_ms,
        durable_commit: proof.state.durable_commit,
        state_root: proof.state.state_root,
        fence_class,
    })
}

fn validate_quorum(
    proof: &PromotionProof,
    policy: &SafetyPolicy,
) -> Result<BTreeSet<NodeId>, ProofError> {
    let mut unique = BTreeSet::new();
    for voter in &proof.quorum.voters {
        if !policy.voters.contains(voter) {
            return Err(ProofError::UnknownVoter);
        }
        if !unique.insert(voter.clone()) {
            return Err(ProofError::DuplicateVoter);
        }
    }
    if unique.len() < policy.quorum_size {
        return Err(ProofError::InsufficientQuorum);
    }
    if !unique.contains(&proof.candidate) {
        return Err(ProofError::CandidateDidNotVote);
    }
    if policy
        .required_witness
        .as_ref()
        .is_some_and(|witness| !unique.contains(witness))
    {
        return Err(ProofError::MissingWitness);
    }
    Ok(unique)
}

fn validate_fence(
    proof: &PromotionProof,
    current: &AuthorityState,
    policy: &SafetyPolicy,
    quorum: &BTreeSet<NodeId>,
    now_ms: u64,
) -> Result<(FenceClass, u64), ProofError> {
    if !policy.voters.contains(&proof.fence.verifier)
        || !quorum.contains(&proof.fence.verifier)
        || policy
            .required_witness
            .as_ref()
            .is_some_and(|witness| witness != &proof.fence.verifier)
    {
        return Err(ProofError::InvalidFenceVerifier);
    }
    validate_fresh(
        proof.fence.observed_at_ms,
        now_ms,
        policy.max_evidence_age_ms,
    )?;

    match (&current.holder, &proof.fence.mechanism) {
        (None, FenceMechanism::Bootstrap)
            if current.epoch == Epoch(0) && proof.fence.target.is_none() =>
        {
            Ok((FenceClass::Bootstrap, proof.fence.observed_at_ms))
        }
        (None, _) => Err(ProofError::InvalidBootstrap),
        (Some(_), FenceMechanism::Bootstrap) => Err(ProofError::BootstrapNotAllowed),
        (Some(holder), mechanism) => {
            if proof.fence.target.as_ref() != Some(holder) {
                return Err(ProofError::WrongFenceTarget);
            }
            match mechanism {
                FenceMechanism::HardwarePower => {
                    Ok((FenceClass::HardwarePower, proof.fence.observed_at_ms))
                }
                FenceMechanism::StorageReservation => Ok((
                    FenceClass::StorageReservation,
                    proof.fence.observed_at_ms,
                )),
                FenceMechanism::EffectGateExpired => {
                    if !policy.allow_gate_expiry_fence {
                        return Err(ProofError::GateExpiryFenceDisabled);
                    }
                    let previous_lease_expires_at_ms = current
                        .lease_expires_at_ms
                        .ok_or(ProofError::FenceGuardNotElapsed)?;
                    let safe_time = previous_lease_expires_at_ms
                        .checked_add(policy.lease_guard_ms)
                        .ok_or(ProofError::FenceGuardNotElapsed)?;
                    if now_ms < safe_time {
                        return Err(ProofError::FenceGuardNotElapsed);
                    }
                    Ok((FenceClass::EffectGateExpiry, safe_time))
                }
                FenceMechanism::GracefulShutdown => Err(ProofError::WeakFence),
                FenceMechanism::Bootstrap => Err(ProofError::BootstrapNotAllowed),
            }
        }
    }
}

fn validate_health(
    proof: &PromotionProof,
    policy: &SafetyPolicy,
    now_ms: u64,
) -> Result<(), ProofError> {
    if proof.health.workload != proof.workload
        || proof.health.node != proof.candidate
        || proof.health.incarnation != proof.candidate_incarnation
    {
        return Err(ProofError::HealthSubjectMismatch);
    }
    validate_fresh(
        proof.health.observed_at_ms,
        now_ms,
        policy.max_evidence_age_ms,
    )?;
    if !proof.health.healthy {
        return Err(ProofError::CandidateUnhealthy);
    }
    if proof.health.passed_checks < policy.min_health_checks {
        return Err(ProofError::InsufficientHealthChecks);
    }
    Ok(())
}

fn validate_lease(
    proof: &PromotionProof,
    policy: &SafetyPolicy,
    safe_not_before_ms: u64,
    now_ms: u64,
) -> Result<(), ProofError> {
    if proof.lease.workload != proof.workload
        || proof.lease.holder != proof.candidate
        || proof.lease.incarnation != proof.candidate_incarnation
    {
        return Err(ProofError::LeaseSubjectMismatch);
    }
    let duration = proof
        .lease
        .expires_at_ms
        .checked_sub(proof.lease.not_before_ms)
        .ok_or(ProofError::InvalidLeaseInterval)?;
    if duration == 0 {
        return Err(ProofError::InvalidLeaseInterval);
    }
    if duration > policy.max_lease_duration_ms {
        return Err(ProofError::LeaseTooLong);
    }
    if proof.lease.not_before_ms < safe_not_before_ms {
        return Err(ProofError::LeaseStartsBeforeFence);
    }
    if now_ms < proof.lease.not_before_ms || now_ms >= proof.lease.expires_at_ms {
        return Err(ProofError::LeaseNotActive);
    }
    Ok(())
}

fn validate_fresh(observed_at_ms: u64, now_ms: u64, max_age_ms: u64) -> Result<(), ProofError> {
    let age = now_ms
        .checked_sub(observed_at_ms)
        .ok_or(ProofError::EvidenceFromFuture)?;
    if age > max_age_ms {
        return Err(ProofError::EvidenceTooOld);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 10_000;

    fn node(value: &str) -> NodeId {
        let Ok(identifier) = NodeId::new(value) else {
            std::process::abort();
        };
        identifier
    }

    fn workload() -> WorkloadId {
        let Ok(identifier) = WorkloadId::new("orders") else {
            std::process::abort();
        };
        identifier
    }

    fn hash() -> PolicyHash {
        PolicyHash::new([7; 32])
    }

    fn policy() -> SafetyPolicy {
        let result = SafetyPolicy::new(
            workload(),
            hash(),
            [node("node-a"), node("node-b")],
            [node("node-a"), node("node-b"), node("witness")],
            2,
            Some(node("witness")),
            3,
            1_000,
            2_000,
            100,
            true,
        );
        let Ok(policy) = result else {
            std::process::abort();
        };
        policy
    }

    fn proof(candidate: &str, epoch: u64) -> PromotionProof {
        let candidate = node(candidate);
        PromotionProof {
            workload: workload(),
            candidate: candidate.clone(),
            candidate_incarnation: Incarnation(1),
            epoch: Epoch(epoch),
            policy_hash: hash(),
            quorum: QuorumCertificate {
                epoch: Epoch(epoch),
                workload: workload(),
                candidate: candidate.clone(),
                candidate_incarnation: Incarnation(1),
                policy_hash: hash(),
                required_commit: CommitIndex(42),
                state_root: StateRoot::new([9; 32]),
                lease_not_before_ms: NOW - 5,
                lease_expires_at_ms: NOW + 500,
                voters: vec![candidate.clone(), node("witness")],
            },
            fence: FenceReceipt {
                epoch: Epoch(epoch),
                target: None,
                verifier: node("witness"),
                mechanism: FenceMechanism::Bootstrap,
                observed_at_ms: NOW - 10,
            },
            state: StateEvidence {
                required_commit: CommitIndex(42),
                durable_commit: CommitIndex(42),
                state_root: StateRoot::new([9; 32]),
                observed_at_ms: NOW - 10,
            },
            health: HealthAttestation {
                workload: workload(),
                node: candidate.clone(),
                incarnation: Incarnation(1),
                epoch: Epoch(epoch),
                healthy: true,
                passed_checks: 3,
                observed_at_ms: NOW - 10,
            },
            lease: LeaseGrant {
                workload: workload(),
                holder: candidate,
                incarnation: Incarnation(1),
                epoch: Epoch(epoch),
                not_before_ms: NOW - 5,
                expires_at_ms: NOW + 500,
            },
        }
    }

    #[test]
    fn valid_bootstrap_proof_is_accepted() {
        let result = validate_promotion(
            &proof("node-a", 1),
            &AuthorityState::initial(),
            &policy(),
            NOW,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn stale_epoch_is_rejected() {
        let current = AuthorityState {
            epoch: Epoch(2),
            holder: Some(node("node-a")),
            lease_expires_at_ms: Some(NOW - 100),
        };
        assert_eq!(
            validate_promotion(&proof("node-b", 2), &current, &policy(), NOW),
            Err(ProofError::StaleEpoch)
        );
    }

    #[test]
    fn duplicate_vote_is_rejected_before_counting() {
        let mut candidate = proof("node-a", 1);
        candidate.quorum.voters = vec![node("node-a"), node("witness"), node("witness")];
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::DuplicateVoter)
        );
    }

    #[test]
    fn missing_witness_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.quorum.voters = vec![node("node-a"), node("node-b")];
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::MissingWitness)
        );
    }

    #[test]
    fn lagging_state_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.state.durable_commit = CommitIndex(41);
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::CandidateStateBehind)
        );
    }

    #[test]
    fn zero_state_root_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.state.state_root = StateRoot::new([0; 32]);
        candidate.quorum.state_root = StateRoot::new([0; 32]);
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::EmptyStateRoot)
        );
    }

    #[test]
    fn weak_fence_is_rejected() {
        let current = AuthorityState {
            epoch: Epoch(1),
            holder: Some(node("node-a")),
            lease_expires_at_ms: Some(NOW - 200),
        };
        let mut candidate = proof("node-b", 2);
        candidate.fence.target = Some(node("node-a"));
        candidate.fence.mechanism = FenceMechanism::GracefulShutdown;
        assert_eq!(
            validate_promotion(&candidate, &current, &policy(), NOW),
            Err(ProofError::WeakFence)
        );
    }

    #[test]
    fn gate_expiry_requires_guard_interval() {
        let current = AuthorityState {
            epoch: Epoch(1),
            holder: Some(node("node-a")),
            lease_expires_at_ms: Some(NOW - 50),
        };
        let mut candidate = proof("node-b", 2);
        candidate.fence.target = Some(node("node-a"));
        candidate.fence.mechanism = FenceMechanism::EffectGateExpired;
        assert_eq!(
            validate_promotion(&candidate, &current, &policy(), NOW),
            Err(ProofError::FenceGuardNotElapsed)
        );
    }

    #[test]
    fn hardware_fence_allows_next_epoch() {
        let current = AuthorityState {
            epoch: Epoch(1),
            holder: Some(node("node-a")),
            lease_expires_at_ms: Some(NOW - 100),
        };
        let mut candidate = proof("node-b", 2);
        candidate.fence.target = Some(node("node-a"));
        candidate.fence.mechanism = FenceMechanism::HardwarePower;
        assert!(validate_promotion(&candidate, &current, &policy(), NOW).is_ok());
    }

    #[test]
    fn inactive_lease_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.lease.not_before_ms = NOW + 1;
        candidate.lease.expires_at_ms = NOW + 500;
        candidate.quorum.lease_not_before_ms = NOW + 1;
        candidate.quorum.lease_expires_at_ms = NOW + 500;
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::LeaseNotActive)
        );
    }

    #[test]
    fn unhealthy_candidate_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.health.healthy = false;
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::CandidateUnhealthy)
        );
    }

    #[test]
    fn future_evidence_is_rejected() {
        let mut candidate = proof("node-a", 1);
        candidate.state.observed_at_ms = NOW + 1;
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::EvidenceFromFuture)
        );
    }

    #[test]
    fn candidate_cannot_lower_quorum_required_commit() {
        let mut candidate = proof("node-a", 1);
        candidate.state.required_commit = CommitIndex(1);
        assert_eq!(
            validate_promotion(&candidate, &AuthorityState::initial(), &policy(), NOW),
            Err(ProofError::QuorumBindingMismatch)
        );
    }
}
