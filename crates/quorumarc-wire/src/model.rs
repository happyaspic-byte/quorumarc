use std::cmp::Ordering;
use std::fmt::{self, Display, Formatter};

use crate::EnvelopeError;

/// The only promotion-envelope protocol version accepted by this crate.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum number of distinct voters carried in one quorum certificate.
pub const MAX_VOTES: usize = 64;

/// Identifier encoded as a length-prefixed canonical ASCII string.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CanonicalId(String);

impl CanonicalId {
    /// Constructs an identifier accepted by the canonical wire format.
    pub fn new(value: impl Into<String>) -> Result<Self, EnvelopeError> {
        let value = value.into();
        if value.is_empty() {
            return Err(EnvelopeError::EmptyIdentifier);
        }
        if value.len() > 128 {
            return Err(EnvelopeError::IdentifierTooLong);
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(EnvelopeError::InvalidIdentifierCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Display for CanonicalId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Replay-relevant identifier for one promotion attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MessageId([u8; 16]);

impl MessageId {
    /// Constructs a message ID. The all-zero sentinel is rejected during validation.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width message ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<(), EnvelopeError> {
        if self.0.iter().all(|byte| *byte == 0) {
            return Err(EnvelopeError::ZeroMessageId);
        }
        Ok(())
    }
}

/// Stable, signed description of the promotion on which voters agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumBinding {
    /// Exact wire protocol version.
    pub protocol_version: u16,
    /// Unique promotion-attempt identity.
    pub message_id: MessageId,
    /// Protected workload identity.
    pub workload_id: CanonicalId,
    /// Proposed authority holder.
    pub candidate_node_id: CanonicalId,
    /// Durable candidate boot generation.
    pub candidate_incarnation: u64,
    /// Proposed authority generation.
    pub epoch: u64,
    /// Digest of the exact safety policy.
    pub policy_hash: [u8; 32],
    /// Commit index required for promotion.
    pub required_commit: u64,
    /// Commit index reported durable by the candidate.
    pub durable_commit: u64,
    /// Digest of the required committed state.
    pub state_root: [u8; 32],
    /// Inclusive start of the authority lease.
    pub lease_not_before_ms: u64,
    /// Exclusive end of the authority lease.
    pub lease_expires_at_ms: u64,
}

impl QuorumBinding {
    pub(crate) fn validate(&self) -> Result<(), EnvelopeError> {
        validate_version(self.protocol_version)?;
        self.message_id.validate()?;
        if self.candidate_incarnation == 0 {
            return Err(EnvelopeError::ZeroIncarnation);
        }
        if self.epoch == 0 {
            return Err(EnvelopeError::ZeroEpoch);
        }
        validate_digest(&self.policy_hash, "policy hash")?;
        validate_digest(&self.state_root, "state root")?;
        if self.durable_commit < self.required_commit {
            return Err(EnvelopeError::CandidateStateBehind);
        }
        validate_lease(self.lease_not_before_ms, self.lease_expires_at_ms)
    }
}

/// Ed25519 vote over a [`QuorumBinding`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedVote {
    pub(crate) voter_id: CanonicalId,
    pub(crate) key_id: CanonicalId,
    pub(crate) signature: [u8; 64],
}

impl SignedVote {
    /// Identity that issued this vote.
    #[must_use]
    pub fn voter_id(&self) -> &CanonicalId {
        &self.voter_id
    }

    /// Rotation-aware identifier of the signing key.
    #[must_use]
    pub fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    /// Raw Ed25519 signature bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Voter signatures and the complete statement to which they are bound.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuorumCertificate {
    /// Common vote statement.
    pub binding: QuorumBinding,
    /// Policy-required number of votes.
    pub threshold: u16,
    pub(crate) votes: Vec<SignedVote>,
}

impl QuorumCertificate {
    /// Builds a certificate after enforcing canonical voter ordering and threshold bounds.
    pub fn new(
        binding: QuorumBinding,
        threshold: u16,
        votes: Vec<SignedVote>,
    ) -> Result<Self, EnvelopeError> {
        let certificate = Self {
            binding,
            threshold,
            votes,
        };
        certificate.validate()?;
        Ok(certificate)
    }

    /// Signed votes in their strict canonical voter order.
    #[must_use]
    pub fn votes(&self) -> &[SignedVote] {
        &self.votes
    }

    pub(crate) fn validate(&self) -> Result<(), EnvelopeError> {
        self.binding.validate()?;
        if self.votes.len() > MAX_VOTES {
            return Err(EnvelopeError::TooManyVotes);
        }
        if self.threshold == 0 || usize::from(self.threshold) > self.votes.len() {
            return Err(EnvelopeError::InvalidQuorumThreshold);
        }
        for pair in self.votes.windows(2) {
            let [first, second] = pair else {
                return Err(EnvelopeError::NonCanonicalVoterOrder);
            };
            let ordering = first.voter_id.cmp(&second.voter_id);
            if ordering == Ordering::Equal {
                return Err(EnvelopeError::DuplicateVoter);
            }
            if ordering == Ordering::Greater {
                return Err(EnvelopeError::NonCanonicalVoterOrder);
            }
        }
        Ok(())
    }
}

/// Fence mechanism whose stable numeric tag is part of the signed wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FenceMechanism {
    /// First activation, when no old authority exists.
    Bootstrap,
    /// Hardware controller verified that the prior host is powered off.
    HardwarePower,
    /// Exclusive storage authority was revoked from the prior host.
    StorageReservation,
    /// An independently enforced EffectGate lease and guard interval expired.
    EffectGateExpired,
}

impl FenceMechanism {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Bootstrap => 0,
            Self::HardwarePower => 1,
            Self::StorageReservation => 2,
            Self::EffectGateExpired => 3,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self, EnvelopeError> {
        match tag {
            0 => Ok(Self::Bootstrap),
            1 => Ok(Self::HardwarePower),
            2 => Ok(Self::StorageReservation),
            3 => Ok(Self::EffectGateExpired),
            _ => Err(EnvelopeError::UnknownFenceMechanism(tag)),
        }
    }
}

/// Verifier-signed evidence that the previous authority cannot create effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FenceReceipt {
    pub(crate) target: Option<CanonicalId>,
    pub(crate) verifier_id: CanonicalId,
    pub(crate) key_id: CanonicalId,
    pub(crate) mechanism: FenceMechanism,
    pub(crate) observed_at_ms: u64,
    pub(crate) evidence_digest: [u8; 32],
    pub(crate) signature: [u8; 64],
}

impl FenceReceipt {
    /// Previously authoritative node, absent only for bootstrap.
    #[must_use]
    pub fn target(&self) -> Option<&CanonicalId> {
        self.target.as_ref()
    }

    /// Identity that verified the fence.
    #[must_use]
    pub fn verifier_id(&self) -> &CanonicalId {
        &self.verifier_id
    }

    /// Rotation-aware identifier of the verifier key.
    #[must_use]
    pub fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    /// Verified fence class.
    #[must_use]
    pub const fn mechanism(&self) -> FenceMechanism {
        self.mechanism
    }

    /// Monotonic-domain observation time supplied by the verifier.
    #[must_use]
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    /// Digest of mechanism-specific evidence retained outside the envelope.
    #[must_use]
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }

    /// Raw Ed25519 signature bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }

    pub(crate) fn validate_structure(&self) -> Result<(), EnvelopeError> {
        match (self.mechanism, self.target.as_ref()) {
            (FenceMechanism::Bootstrap, None) => {}
            (FenceMechanism::Bootstrap, Some(_)) | (_, None) => {
                return Err(EnvelopeError::InvalidFenceTarget);
            }
            (_, Some(_)) => {}
        }
        validate_digest(&self.evidence_digest, "fence evidence digest")
    }
}

/// Workload-specific readiness evidence bound by the candidate signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HealthAttestation {
    /// Node whose workload instance was checked.
    pub node_id: CanonicalId,
    /// Checked boot generation.
    pub incarnation: u64,
    /// Checked authority generation.
    pub epoch: u64,
    /// Aggregate readiness result.
    pub healthy: bool,
    /// Number of policy-required checks that passed.
    pub passed_checks: u16,
    /// Observation time in the attestor's monotonic domain.
    pub observed_at_ms: u64,
    /// Digest of the complete health result.
    pub attestation_digest: [u8; 32],
}

/// Bounded grant checked before producing an external effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeaseGrant {
    /// Authorized node.
    pub holder_node_id: CanonicalId,
    /// Authorized boot generation.
    pub incarnation: u64,
    /// Authorized authority generation.
    pub epoch: u64,
    /// Inclusive grant start.
    pub not_before_ms: u64,
    /// Exclusive grant end.
    pub expires_at_ms: u64,
}

/// Complete, deterministic promotion statement before the candidate signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionEnvelope {
    /// Exact wire protocol version.
    pub protocol_version: u16,
    /// Unique identity used by durable replay protection.
    pub message_id: MessageId,
    /// Protected workload.
    pub workload_id: CanonicalId,
    /// Proposed authority holder.
    pub candidate_node_id: CanonicalId,
    /// Durable candidate boot generation.
    pub candidate_incarnation: u64,
    /// Proposed authority generation.
    pub epoch: u64,
    /// Digest of the exact policy used to authorize promotion.
    pub policy_hash: [u8; 32],
    /// Voter-signed promotion statement.
    pub quorum_certificate: QuorumCertificate,
    /// Verifier-signed exclusion evidence for the prior holder.
    pub fence_receipt: FenceReceipt,
    /// Minimum commit required by the voters.
    pub required_commit: u64,
    /// Commit durably present on the candidate.
    pub durable_commit: u64,
    /// Digest of the required committed state.
    pub state_root: [u8; 32],
    /// Workload readiness evidence.
    pub health_attestation: HealthAttestation,
    /// Bounded authority interval.
    pub lease: LeaseGrant,
}

impl PromotionEnvelope {
    /// Validates all same-envelope bindings and canonical structural invariants.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        validate_version(self.protocol_version)?;
        self.message_id.validate()?;
        if self.candidate_incarnation == 0 {
            return Err(EnvelopeError::ZeroIncarnation);
        }
        if self.epoch == 0 {
            return Err(EnvelopeError::ZeroEpoch);
        }
        validate_digest(&self.policy_hash, "policy hash")?;
        validate_digest(&self.state_root, "state root")?;
        if self.durable_commit < self.required_commit {
            return Err(EnvelopeError::CandidateStateBehind);
        }
        self.quorum_certificate.validate()?;
        self.validate_quorum_binding()?;
        self.fence_receipt.validate_structure()?;
        if !self
            .quorum_certificate
            .votes
            .iter()
            .any(|vote| vote.voter_id == self.fence_receipt.verifier_id)
        {
            return Err(EnvelopeError::FenceVerifierNotInQuorum);
        }
        if self.health_attestation.node_id != self.candidate_node_id {
            return Err(EnvelopeError::BindingMismatch("health node"));
        }
        if self.health_attestation.incarnation != self.candidate_incarnation {
            return Err(EnvelopeError::BindingMismatch("health incarnation"));
        }
        if self.health_attestation.epoch != self.epoch {
            return Err(EnvelopeError::BindingMismatch("health epoch"));
        }
        if !self.health_attestation.healthy || self.health_attestation.passed_checks == 0 {
            return Err(EnvelopeError::InvalidHealthAttestation);
        }
        validate_digest(
            &self.health_attestation.attestation_digest,
            "health attestation digest",
        )?;
        if self.lease.holder_node_id != self.candidate_node_id {
            return Err(EnvelopeError::BindingMismatch("lease holder"));
        }
        if self.lease.incarnation != self.candidate_incarnation {
            return Err(EnvelopeError::BindingMismatch("lease incarnation"));
        }
        if self.lease.epoch != self.epoch {
            return Err(EnvelopeError::BindingMismatch("lease epoch"));
        }
        validate_lease(self.lease.not_before_ms, self.lease.expires_at_ms)
    }

    fn validate_quorum_binding(&self) -> Result<(), EnvelopeError> {
        let binding = &self.quorum_certificate.binding;
        ensure_equal(
            binding.protocol_version,
            self.protocol_version,
            "quorum protocol version",
        )?;
        ensure_equal(binding.message_id, self.message_id, "quorum message ID")?;
        ensure_equal(&binding.workload_id, &self.workload_id, "quorum workload")?;
        ensure_equal(
            &binding.candidate_node_id,
            &self.candidate_node_id,
            "quorum candidate",
        )?;
        ensure_equal(
            binding.candidate_incarnation,
            self.candidate_incarnation,
            "quorum incarnation",
        )?;
        ensure_equal(binding.epoch, self.epoch, "quorum epoch")?;
        ensure_equal(binding.policy_hash, self.policy_hash, "quorum policy hash")?;
        ensure_equal(
            binding.required_commit,
            self.required_commit,
            "quorum required commit",
        )?;
        ensure_equal(
            binding.durable_commit,
            self.durable_commit,
            "quorum durable commit",
        )?;
        ensure_equal(binding.state_root, self.state_root, "quorum state root")?;
        ensure_equal(
            binding.lease_not_before_ms,
            self.lease.not_before_ms,
            "quorum lease start",
        )?;
        ensure_equal(
            binding.lease_expires_at_ms,
            self.lease.expires_at_ms,
            "quorum lease expiry",
        )
    }
}

pub(crate) fn validate_version(version: u16) -> Result<(), EnvelopeError> {
    if version != PROTOCOL_VERSION {
        return Err(EnvelopeError::UnsupportedVersion(version));
    }
    Ok(())
}

pub(crate) fn validate_digest(digest: &[u8; 32], field: &'static str) -> Result<(), EnvelopeError> {
    if digest.iter().all(|byte| *byte == 0) {
        return Err(EnvelopeError::ZeroDigest(field));
    }
    Ok(())
}

fn validate_lease(not_before_ms: u64, expires_at_ms: u64) -> Result<(), EnvelopeError> {
    if expires_at_ms <= not_before_ms {
        return Err(EnvelopeError::InvalidLeaseInterval);
    }
    Ok(())
}

fn ensure_equal<T: PartialEq>(left: T, right: T, field: &'static str) -> Result<(), EnvelopeError> {
    if left != right {
        return Err(EnvelopeError::BindingMismatch(field));
    }
    Ok(())
}
