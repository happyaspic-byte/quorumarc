use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::PathBuf;

use quorumarc_store::{
    DurableAuthorityStore, StorageBackend, StoreError, StoreIdentity, StoreRole, TransitionOutcome,
    VoteRecord,
};
use quorumarc_wire::{CanonicalId, PROTOCOL_VERSION, QuorumBinding, SignedVote, SigningKey};

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
        store_identity: StoreIdentity,
        backend: B,
    ) -> Result<Self, WitnessOpenError> {
        if store_identity.role() != StoreRole::Witness
            || store_identity.node_id() != policy.witness_id.as_str()
            || store_identity.workload_id() != policy.workload_id.as_str()
        {
            return Err(WitnessOpenError::identity_policy_mismatch(
                &policy,
                store_identity,
            ));
        }
        let store = DurableAuthorityStore::open_in(directory, store_identity, backend)
            .map_err(WitnessOpenError::from_store)?;
        Ok(Self {
            policy,
            signing_key,
            store,
        })
    }

    /// Returns the refusal code for a binding that cannot reach durable voting.
    #[must_use]
    pub fn preflight_vote(&self, binding: &QuorumBinding) -> Option<VoteReasonCode> {
        if !binding_is_structurally_valid(binding) {
            return Some(VoteReasonCode::RefusedMalformedBinding);
        }
        if binding.workload_id != self.policy.workload_id {
            return Some(VoteReasonCode::RefusedWorkloadMismatch);
        }
        if binding.policy_hash != self.policy.policy_hash {
            return Some(VoteReasonCode::RefusedPolicyMismatch);
        }
        if !self
            .policy
            .allowed_candidates
            .contains(&binding.candidate_node_id)
        {
            return Some(VoteReasonCode::RefusedCandidateNotAllowed);
        }
        let Some(lease_duration) = binding
            .lease_expires_at_ms
            .checked_sub(binding.lease_not_before_ms)
        else {
            return Some(VoteReasonCode::RefusedMalformedBinding);
        };
        if lease_duration > self.policy.max_lease_duration_ms {
            return Some(VoteReasonCode::RefusedLeaseTooLong);
        }
        let proposal_digest = match binding.proposal_digest() {
            Ok(digest) => digest,
            Err(_) => return Some(VoteReasonCode::RefusedMalformedBinding),
        };
        let record = match VoteRecord::new(
            binding.epoch,
            binding.candidate_node_id.as_str(),
            proposal_digest,
        ) {
            Ok(record) => record,
            Err(_) => return Some(VoteReasonCode::RefusedMalformedBinding),
        };
        self.store
            .preflight_vote(&record)
            .err()
            .map(|error| map_store_error(&error))
    }

    /// Evaluates, persists, then returns a signed vote.
    ///
    /// Signature creation occurs only after `record_vote` supplies a
    /// durability receipt.
    pub fn handle_vote(&mut self, binding: &QuorumBinding) -> VoteReply {
        if let Some(code) = self.preflight_vote(binding) {
            return VoteReply::refused(code);
        }
        let proposal_digest = match binding.proposal_digest() {
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

    /// Whether policy admits exactly the supplied candidate identities.
    #[must_use]
    pub fn policy_matches_candidates<'a>(
        &self,
        candidates: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        let candidates = candidates.into_iter().collect::<BTreeSet<_>>();
        self.policy.allowed_candidates.len() == candidates.len()
            && self
                .policy
                .allowed_candidates
                .iter()
                .all(|candidate| candidates.contains(candidate.as_str()))
    }

    /// Highest epoch known durable by this actor.
    #[must_use]
    pub const fn highest_durable_epoch(&self) -> u64 {
        self.store.state().highest_epoch()
    }

    /// Candidate bound to the most recent durable vote, when one exists.
    ///
    /// Lifecycle coordinators may use this only to validate the target of a
    /// subsequent fence receipt. The returned identity is not, by itself,
    /// proof that the candidate ever activated or still holds authority.
    #[must_use]
    pub fn last_durable_candidate(&self) -> Option<&str> {
        self.store
            .state()
            .last_vote()
            .map(quorumarc_store::VoteRecord::candidate)
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

fn map_store_error(error: &StoreError) -> VoteReasonCode {
    match error {
        StoreError::StaleEpoch { .. } => VoteReasonCode::RefusedStaleEpoch,
        StoreError::DoubleVote { .. } => VoteReasonCode::RefusedConflictSameEpoch,
        StoreError::EpochAlreadyAccepted { .. } => VoteReasonCode::RefusedEpochAlreadyAccepted,
        StoreError::Poisoned => VoteReasonCode::RefusedStorePoisoned,
        StoreError::Io { .. } => VoteReasonCode::RefusedDurabilityIo,
        StoreError::GenerationExhausted => VoteReasonCode::RefusedGenerationExhausted,
        StoreError::Corrupt(_)
        | StoreError::IdentityMismatch { .. }
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
    /// Configured store identity contradicts the Witness policy or durable frame.
    IdentityPolicyMismatch,
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
            Self::IdentityPolicyMismatch => "WITNESS_OPEN_REFUSED_IDENTITY_POLICY_MISMATCH",
            Self::StoreInvariant => "WITNESS_OPEN_REFUSED_STORE_INVARIANT",
        }
    }
}

#[derive(Debug)]
enum WitnessOpenCause {
    Store(StoreError),
    IdentityPolicyMismatch {
        policy_witness_id: String,
        policy_workload_id: String,
        identity: Box<StoreIdentity>,
    },
}

impl Display for WitnessOpenCause {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => Display::fmt(error, formatter),
            Self::IdentityPolicyMismatch {
                policy_witness_id,
                policy_workload_id,
                identity,
            } => write!(
                formatter,
                "witness policy expects node={policy_witness_id} workload={policy_workload_id} role=witness but store identity has node={} workload={} role={}",
                identity.node_id(),
                identity.workload_id(),
                identity.role(),
            ),
        }
    }
}

impl Error for WitnessOpenCause {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::IdentityPolicyMismatch { .. } => None,
        }
    }
}

/// Fail-closed witness recovery error retaining its store cause.
#[derive(Debug)]
pub struct WitnessOpenError {
    code: WitnessOpenReasonCode,
    cause: WitnessOpenCause,
}

impl WitnessOpenError {
    fn from_store(source: StoreError) -> Self {
        let code = match &source {
            StoreError::Corrupt(_) => WitnessOpenReasonCode::CorruptAuthorityState,
            StoreError::Io { .. } => WitnessOpenReasonCode::StorageIo,
            StoreError::IdentityMismatch { .. } => WitnessOpenReasonCode::IdentityPolicyMismatch,
            _ => WitnessOpenReasonCode::StoreInvariant,
        };
        Self {
            code,
            cause: WitnessOpenCause::Store(source),
        }
    }

    fn identity_policy_mismatch(policy: &WitnessPolicy, identity: StoreIdentity) -> Self {
        Self {
            code: WitnessOpenReasonCode::IdentityPolicyMismatch,
            cause: WitnessOpenCause::IdentityPolicyMismatch {
                policy_witness_id: policy.witness_id.as_str().to_owned(),
                policy_workload_id: policy.workload_id.as_str().to_owned(),
                identity: Box::new(identity),
            },
        }
    }

    /// Stable recovery refusal code.
    #[must_use]
    pub const fn code(&self) -> WitnessOpenReasonCode {
        self.code
    }
}

impl Display for WitnessOpenError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.cause)
    }
}

impl Error for WitnessOpenError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
