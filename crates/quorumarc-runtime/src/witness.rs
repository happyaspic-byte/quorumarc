use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use quorumarc_store::{
    DurableAuthorityStore, StorageBackend, StoreError, TransitionOutcome, VoteRecord,
};
use quorumarc_wire::{
    CanonicalId, EnvelopeError, PROTOCOL_VERSION, QuorumBinding, SignedVote, SigningKey,
};
use sha2::{Digest, Sha256};

const BINDING_DIGEST_DOMAIN: &[u8] = b"quorumarc/witness-binding/sha256/v1\0";

/// Immutable admission rules enforced before the lab witness votes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessPolicy {
    witness_id: CanonicalId,
    key_id: CanonicalId,
    workload_id: CanonicalId,
    policy_hash: [u8; 32],
    allowed_candidates: BTreeSet<CanonicalId>,
    max_lease_duration_ms: u64,
}

impl WitnessPolicy {
    /// Validates the narrow policy enforced by the Gate 1A.0 witness actor.
    pub fn new(
        witness_id: CanonicalId,
        key_id: CanonicalId,
        workload_id: CanonicalId,
        policy_hash: [u8; 32],
        allowed_candidates: impl IntoIterator<Item = CanonicalId>,
        max_lease_duration_ms: u64,
    ) -> Result<Self, WitnessPolicyError> {
        let allowed_candidates = allowed_candidates.into_iter().collect::<BTreeSet<_>>();
        if policy_hash.iter().all(|byte| *byte == 0) {
            return Err(WitnessPolicyError::ZeroPolicyHash);
        }
        if allowed_candidates.is_empty() {
            return Err(WitnessPolicyError::NoCandidates);
        }
        if allowed_candidates.contains(&witness_id) {
            return Err(WitnessPolicyError::WitnessIsCandidate);
        }
        if max_lease_duration_ms == 0 {
            return Err(WitnessPolicyError::ZeroLeaseDuration);
        }
        Ok(Self {
            witness_id,
            key_id,
            workload_id,
            policy_hash,
            allowed_candidates,
            max_lease_duration_ms,
        })
    }

    /// Witness identity used in the signed response.
    #[must_use]
    pub const fn witness_id(&self) -> &CanonicalId {
        &self.witness_id
    }

    /// Rotation-aware signing-key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    /// Workload admitted by this witness instance.
    #[must_use]
    pub const fn workload_id(&self) -> &CanonicalId {
        &self.workload_id
    }

    /// Pinned policy digest.
    #[must_use]
    pub const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }
}

/// Invalid witness actor policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessPolicyError {
    /// Policy digest used the all-zero sentinel.
    ZeroPolicyHash,
    /// No candidate could ever be granted a vote.
    NoCandidates,
    /// A witness must never become a workload candidate.
    WitnessIsCandidate,
    /// A zero lease bound cannot admit any useful authority interval.
    ZeroLeaseDuration,
}

impl Display for WitnessPolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroPolicyHash => "witness policy hash is the zero sentinel",
            Self::NoCandidates => "witness policy has no candidates",
            Self::WitnessIsCandidate => "witness identity is also a workload candidate",
            Self::ZeroLeaseDuration => "witness maximum lease duration is zero",
        })
    }
}

impl Error for WitnessPolicyError {}

/// Stable reason code returned for every witness vote decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteReasonCode {
    /// New vote was synchronously committed before the response was returned.
    GrantedDurablyRecorded,
    /// Exact retry matched an already durable vote.
    GrantedAlreadyDurable,
    /// Binding failed canonical structural validation.
    RefusedMalformedBinding,
    /// Binding targets another workload.
    RefusedWorkloadMismatch,
    /// Binding carries another policy digest.
    RefusedPolicyMismatch,
    /// Candidate is not admitted by this witness policy.
    RefusedCandidateNotAllowed,
    /// Requested lease exceeds the witness policy bound.
    RefusedLeaseTooLong,
    /// Requested epoch is behind durable authority state.
    RefusedStaleEpoch,
    /// Another candidate or binding is already durable at this epoch.
    RefusedConflictSameEpoch,
    /// Epoch was durably accepted through another state transition.
    RefusedEpochAlreadyAccepted,
    /// Prior durability failure poisoned the in-process store.
    RefusedStorePoisoned,
    /// Synchronous durability operation failed.
    RefusedDurabilityIo,
    /// Store state or transition contradicted runtime invariants.
    RefusedStoreInvariant,
    /// Durable generation counter cannot advance.
    RefusedGenerationExhausted,
    /// Local signing failed after the vote was made durable.
    RefusedSigningFailure,
}

impl VoteReasonCode {
    /// Stable machine-readable log and reply spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GrantedDurablyRecorded => "VOTE_GRANTED_DURABLY_RECORDED",
            Self::GrantedAlreadyDurable => "VOTE_GRANTED_ALREADY_DURABLE",
            Self::RefusedMalformedBinding => "VOTE_REFUSED_MALFORMED_BINDING",
            Self::RefusedWorkloadMismatch => "VOTE_REFUSED_WORKLOAD_MISMATCH",
            Self::RefusedPolicyMismatch => "VOTE_REFUSED_POLICY_MISMATCH",
            Self::RefusedCandidateNotAllowed => "VOTE_REFUSED_CANDIDATE_NOT_ALLOWED",
            Self::RefusedLeaseTooLong => "VOTE_REFUSED_LEASE_TOO_LONG",
            Self::RefusedStaleEpoch => "VOTE_REFUSED_STALE_EPOCH",
            Self::RefusedConflictSameEpoch => "VOTE_REFUSED_CONFLICT_SAME_EPOCH",
            Self::RefusedEpochAlreadyAccepted => "VOTE_REFUSED_EPOCH_ALREADY_ACCEPTED",
            Self::RefusedStorePoisoned => "VOTE_REFUSED_STORE_POISONED",
            Self::RefusedDurabilityIo => "VOTE_REFUSED_DURABILITY_IO",
            Self::RefusedStoreInvariant => "VOTE_REFUSED_STORE_INVARIANT",
            Self::RefusedGenerationExhausted => "VOTE_REFUSED_GENERATION_EXHAUSTED",
            Self::RefusedSigningFailure => "VOTE_REFUSED_SIGNING_FAILURE",
        }
    }

    /// Whether a signed vote may accompany this code.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        matches!(
            self,
            Self::GrantedDurablyRecorded | Self::GrantedAlreadyDurable
        )
    }
}

/// One witness decision. A signature is present only after durable success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteReply {
    code: VoteReasonCode,
    signed_vote: Option<SignedVote>,
    durable_generation: Option<u64>,
}

impl VoteReply {
    fn granted(code: VoteReasonCode, vote: SignedVote, generation: u64) -> Self {
        Self {
            code,
            signed_vote: Some(vote),
            durable_generation: Some(generation),
        }
    }

    const fn refused(code: VoteReasonCode) -> Self {
        Self {
            code,
            signed_vote: None,
            durable_generation: None,
        }
    }

    /// Stable decision code.
    #[must_use]
    pub const fn code(&self) -> VoteReasonCode {
        self.code
    }

    /// Signed witness vote, available only for a durable grant.
    #[must_use]
    pub const fn signed_vote(&self) -> Option<&SignedVote> {
        self.signed_vote.as_ref()
    }

    /// Durable store generation proving the vote response is replay-safe.
    #[must_use]
    pub const fn durable_generation(&self) -> Option<u64> {
        self.durable_generation
    }

    /// Whether this reply grants the requested vote.
    #[must_use]
    pub const fn is_granted(&self) -> bool {
        self.code.is_granted()
    }
}

/// Witness that signs only after the exact vote binding is known durable.
///
/// This actor is intentionally single-threaded through `&mut self`. A service
/// must serialize access to one actor instance rather than opening several
/// stores against the same directory. The actor validates only its narrow lab
/// policy; it does not establish physical fencing or a production lease clock.
pub struct WitnessVoteActor<B> {
    policy: WitnessPolicy,
    signing_key: SigningKey,
    store: DurableAuthorityStore<B>,
}

impl<B: StorageBackend> WitnessVoteActor<B> {
    /// Opens durable witness state and fails closed on recovery ambiguity.
    pub fn open(
        policy: WitnessPolicy,
        signing_key: SigningKey,
        directory: impl Into<PathBuf>,
        backend: B,
    ) -> Result<Self, WitnessOpenError> {
        let store = DurableAuthorityStore::open_in(directory, backend)
            .map_err(WitnessOpenError::from_store)?;
        Ok(Self {
            policy,
            signing_key,
            store,
        })
    }

    /// Evaluates, persists, then returns a signed vote.
    ///
    /// Signature creation occurs only after `record_vote` supplies a
    /// durability receipt.
    pub fn handle_vote(&mut self, binding: &QuorumBinding) -> VoteReply {
        if !binding_is_structurally_valid(binding) {
            return VoteReply::refused(VoteReasonCode::RefusedMalformedBinding);
        }
        if binding.workload_id != self.policy.workload_id {
            return VoteReply::refused(VoteReasonCode::RefusedWorkloadMismatch);
        }
        if binding.policy_hash != self.policy.policy_hash {
            return VoteReply::refused(VoteReasonCode::RefusedPolicyMismatch);
        }
        if !self
            .policy
            .allowed_candidates
            .contains(&binding.candidate_node_id)
        {
            return VoteReply::refused(VoteReasonCode::RefusedCandidateNotAllowed);
        }
        let Some(lease_duration) = binding
            .lease_expires_at_ms
            .checked_sub(binding.lease_not_before_ms)
        else {
            return VoteReply::refused(VoteReasonCode::RefusedMalformedBinding);
        };
        if lease_duration > self.policy.max_lease_duration_ms {
            return VoteReply::refused(VoteReasonCode::RefusedLeaseTooLong);
        }

        let proposal_digest =
            match binding_digest(binding, &self.policy.witness_id, &self.policy.key_id) {
                Ok(digest) => digest,
                Err(_) => return VoteReply::refused(VoteReasonCode::RefusedMalformedBinding),
            };
        let record = match VoteRecord::new(
            binding.epoch,
            binding.candidate_node_id.as_str(),
            proposal_digest,
        ) {
            Ok(record) => record,
            Err(_) => return VoteReply::refused(VoteReasonCode::RefusedMalformedBinding),
        };

        let receipt = match self.store.record_vote(record) {
            Ok(receipt) => receipt,
            Err(error) => return VoteReply::refused(map_store_error(&error)),
        };
        let signed_vote = match SignedVote::sign(
            binding,
            self.policy.witness_id.clone(),
            self.policy.key_id.clone(),
            &self.signing_key,
        ) {
            Ok(vote) => vote,
            Err(_) => return VoteReply::refused(VoteReasonCode::RefusedSigningFailure),
        };
        let code = match receipt.outcome() {
            TransitionOutcome::Committed => VoteReasonCode::GrantedDurablyRecorded,
            TransitionOutcome::AlreadyDurable => VoteReasonCode::GrantedAlreadyDurable,
        };
        VoteReply::granted(code, signed_vote, receipt.generation())
    }

    /// Highest epoch known durable by this actor.
    #[must_use]
    pub const fn highest_durable_epoch(&self) -> u64 {
        self.store.state().highest_epoch()
    }

    /// Current durable frame generation.
    #[must_use]
    pub const fn durable_generation(&self) -> u64 {
        self.store.generation()
    }

    /// Whether a durability failure has stopped all further writes.
    #[must_use]
    pub const fn is_store_poisoned(&self) -> bool {
        self.store.is_poisoned()
    }
}

fn binding_is_structurally_valid(binding: &QuorumBinding) -> bool {
    binding.protocol_version == PROTOCOL_VERSION
        && binding.message_id.as_bytes().iter().any(|byte| *byte != 0)
        && binding.candidate_incarnation != 0
        && binding.epoch != 0
        && binding.policy_hash.iter().any(|byte| *byte != 0)
        && binding.state_root.iter().any(|byte| *byte != 0)
        && binding.durable_commit >= binding.required_commit
        && binding.lease_expires_at_ms > binding.lease_not_before_ms
}

fn binding_digest(
    binding: &QuorumBinding,
    witness_id: &CanonicalId,
    key_id: &CanonicalId,
) -> Result<[u8; 32], EnvelopeError> {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DIGEST_DOMAIN);
    hasher.update(binding.protocol_version.to_be_bytes());
    hasher.update(binding.message_id.as_bytes());
    hash_id(&mut hasher, &binding.workload_id)?;
    hash_id(&mut hasher, &binding.candidate_node_id)?;
    hasher.update(binding.candidate_incarnation.to_be_bytes());
    hasher.update(binding.epoch.to_be_bytes());
    hasher.update(binding.policy_hash);
    hasher.update(binding.required_commit.to_be_bytes());
    hasher.update(binding.durable_commit.to_be_bytes());
    hasher.update(binding.state_root);
    hasher.update(binding.lease_not_before_ms.to_be_bytes());
    hasher.update(binding.lease_expires_at_ms.to_be_bytes());
    hash_id(&mut hasher, witness_id)?;
    hash_id(&mut hasher, key_id)?;
    Ok(hasher.finalize().into())
}

fn hash_id(hasher: &mut Sha256, identifier: &CanonicalId) -> Result<(), EnvelopeError> {
    let length =
        u16::try_from(identifier.as_str().len()).map_err(|_| EnvelopeError::IdentifierTooLong)?;
    hasher.update(length.to_be_bytes());
    hasher.update(identifier.as_str().as_bytes());
    Ok(())
}

fn map_store_error(error: &StoreError) -> VoteReasonCode {
    match error {
        StoreError::StaleEpoch { .. } => VoteReasonCode::RefusedStaleEpoch,
        StoreError::DoubleVote { .. } => VoteReasonCode::RefusedConflictSameEpoch,
        StoreError::EpochAlreadyAccepted { .. } => VoteReasonCode::RefusedEpochAlreadyAccepted,
        StoreError::Poisoned => VoteReasonCode::RefusedStorePoisoned,
        StoreError::Io { .. } => VoteReasonCode::RefusedDurabilityIo,
        StoreError::GenerationExhausted => VoteReasonCode::RefusedGenerationExhausted,
        StoreError::Corrupt(_)
        | StoreError::MissingVote { .. }
        | StoreError::VoteDigestMismatch { .. }
        | StoreError::ConflictingPromotion { .. }
        | StoreError::StaleIncarnation { .. }
        | StoreError::CommitRegression { .. }
        | StoreError::StateRootConflict { .. }
        | StoreError::ActivationMismatch
        | StoreError::ConflictingActivation { .. }
        | StoreError::InvalidInput(_) => VoteReasonCode::RefusedStoreInvariant,
    }
}

/// Stable reason code for actor recovery refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessOpenReasonCode {
    /// Durable frame was corrupt, truncated, or inconsistent.
    CorruptAuthorityState,
    /// Filesystem recovery I/O failed.
    StorageIo,
    /// Recovery returned an impossible non-recovery store error.
    StoreInvariant,
}

impl WitnessOpenReasonCode {
    /// Stable machine-readable log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorruptAuthorityState => "WITNESS_OPEN_REFUSED_CORRUPT_AUTHORITY_STATE",
            Self::StorageIo => "WITNESS_OPEN_REFUSED_STORAGE_IO",
            Self::StoreInvariant => "WITNESS_OPEN_REFUSED_STORE_INVARIANT",
        }
    }
}

/// Fail-closed witness recovery error retaining its store cause.
#[derive(Debug)]
pub struct WitnessOpenError {
    code: WitnessOpenReasonCode,
    source: StoreError,
}

impl WitnessOpenError {
    fn from_store(source: StoreError) -> Self {
        let code = match &source {
            StoreError::Corrupt(_) => WitnessOpenReasonCode::CorruptAuthorityState,
            StoreError::Io { .. } => WitnessOpenReasonCode::StorageIo,
            _ => WitnessOpenReasonCode::StoreInvariant,
        };
        Self { code, source }
    }

    /// Stable recovery refusal code.
    #[must_use]
    pub const fn code(&self) -> WitnessOpenReasonCode {
        self.code
    }
}

impl Display for WitnessOpenError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.source)
    }
}

impl Error for WitnessOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
