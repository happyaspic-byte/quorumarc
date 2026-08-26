use std::error::Error;
use std::fmt::{self, Display, Formatter};

/// Immutable purpose of one durable authority store.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum StoreRole {
    /// Authority and replicated progress for a workload-capable data node.
    DataNode,
    /// Vote history for a non-workload Witness.
    Witness,
}

impl StoreRole {
    /// Stable human-readable role name used in diagnostics.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DataNode => "data-node",
            Self::Witness => "witness",
        }
    }

    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::DataNode => 1,
            Self::Witness => 2,
        }
    }

    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::DataNode),
            2 => Some(Self::Witness),
            _ => None,
        }
    }
}

impl Display for StoreRole {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Immutable identity bound into every committed authority frame.
///
/// `store_id` is a provisioning identifier, not a secret. Copying both a
/// journal and its complete expected identity remains a perfect clone and
/// requires an external fence or hardware identity to detect.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct StoreIdentity {
    cluster_id: String,
    workload_id: String,
    node_id: String,
    role: StoreRole,
    store_id: [u8; 16],
}

impl StoreIdentity {
    /// Creates a canonical immutable store identity.
    pub fn new(
        cluster_id: impl Into<String>,
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        role: StoreRole,
        store_id: [u8; 16],
    ) -> Result<Self, ModelError> {
        if store_id.iter().all(|byte| *byte == 0) {
            return Err(ModelError::ZeroStoreId);
        }
        Ok(Self {
            cluster_id: validate_identifier(cluster_id.into())?,
            workload_id: validate_identifier(workload_id.into())?,
            node_id: validate_identifier(node_id.into())?,
            role,
            store_id,
        })
    }

    /// Cluster namespace that owns this authority history.
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    /// Workload whose progress and authority are stored.
    #[must_use]
    pub fn workload_id(&self) -> &str {
        &self.workload_id
    }

    /// Logical node allowed to open this store.
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Immutable data-node or Witness purpose.
    #[must_use]
    pub const fn role(&self) -> StoreRole {
        self.role
    }

    /// Provisioned store-instance identifier.
    #[must_use]
    pub const fn store_id(&self) -> &[u8; 16] {
        &self.store_id
    }

    pub(crate) fn from_validated(
        cluster_id: String,
        workload_id: String,
        node_id: String,
        role: StoreRole,
        store_id: [u8; 16],
    ) -> Self {
        Self {
            cluster_id,
            workload_id,
            node_id,
            role,
            store_id,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        Self::new(
            self.cluster_id.clone(),
            self.workload_id.clone(),
            self.node_id.clone(),
            self.role,
            self.store_id,
        )
        .map(|_| ())
    }
}

impl Display for StoreIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "cluster={} workload={} node={} role={} store_id=",
            self.cluster_id, self.workload_id, self.node_id, self.role
        )?;
        for byte in self.store_id {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fixed-width state digest stored with durable commit progress.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StateRoot([u8; 32]);

impl StateRoot {
    /// Constructs a state root supplied by a trusted replication layer.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exclusive authority lease bounds in a trusted time domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LeaseBounds {
    not_before_ms: u64,
    expires_at_ms: u64,
}

impl LeaseBounds {
    /// Creates non-empty lease bounds.
    pub fn new(not_before_ms: u64, expires_at_ms: u64) -> Result<Self, ModelError> {
        if not_before_ms >= expires_at_ms {
            return Err(ModelError::InvalidLease);
        }
        Ok(Self {
            not_before_ms,
            expires_at_ms,
        })
    }

    /// Inclusive lease start.
    #[must_use]
    pub const fn not_before_ms(self) -> u64 {
        self.not_before_ms
    }

    /// Exclusive lease expiry.
    #[must_use]
    pub const fn expires_at_ms(self) -> u64 {
        self.expires_at_ms
    }

    pub(crate) const fn from_validated(not_before_ms: u64, expires_at_ms: u64) -> Self {
        Self {
            not_before_ms,
            expires_at_ms,
        }
    }
}

/// A witness or peer vote persisted before it may be emitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteRecord {
    epoch: u64,
    candidate: String,
    proposal_digest: [u8; 32],
}

impl VoteRecord {
    /// Creates a canonical vote record.
    pub fn new(
        epoch: u64,
        candidate: impl Into<String>,
        proposal_digest: [u8; 32],
    ) -> Result<Self, ModelError> {
        if epoch == 0 {
            return Err(ModelError::ZeroEpoch);
        }
        let candidate = validate_identifier(candidate.into())?;
        Ok(Self {
            epoch,
            candidate,
            proposal_digest,
        })
    }

    /// Epoch for which the vote was issued.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Candidate bound to the vote.
    #[must_use]
    pub fn candidate(&self) -> &str {
        &self.candidate
    }

    /// Digest of the proposal bound to the vote.
    #[must_use]
    pub const fn proposal_digest(&self) -> &[u8; 32] {
        &self.proposal_digest
    }

    pub(crate) fn from_validated(epoch: u64, candidate: String, proposal_digest: [u8; 32]) -> Self {
        Self {
            epoch,
            candidate,
            proposal_digest,
        }
    }
}

/// Promotion material durably accepted for one epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PromotionRecord {
    epoch: u64,
    proposal_digest: [u8; 32],
    signed_envelope_digest: [u8; 32],
    lease: LeaseBounds,
    commit_index: u64,
    state_root: StateRoot,
}

impl PromotionRecord {
    /// Creates a complete promotion record.
    pub fn new(
        epoch: u64,
        proposal_digest: [u8; 32],
        signed_envelope_digest: [u8; 32],
        lease: LeaseBounds,
        commit_index: u64,
        state_root: StateRoot,
    ) -> Result<Self, ModelError> {
        if epoch == 0 {
            return Err(ModelError::ZeroEpoch);
        }
        Ok(Self {
            epoch,
            proposal_digest,
            signed_envelope_digest,
            lease,
            commit_index,
            state_root,
        })
    }

    /// Accepted epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Digest of the pre-certificate quorum proposal accepted by voters.
    #[must_use]
    pub const fn proposal_digest(&self) -> &[u8; 32] {
        &self.proposal_digest
    }

    /// Digest of the complete candidate-signed promotion envelope.
    #[must_use]
    pub const fn signed_envelope_digest(&self) -> &[u8; 32] {
        &self.signed_envelope_digest
    }

    /// Lease bound into the promotion digest.
    #[must_use]
    pub const fn lease(&self) -> LeaseBounds {
        self.lease
    }

    /// Required durable commit at promotion.
    #[must_use]
    pub const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// Required state root at promotion.
    #[must_use]
    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub(crate) const fn from_validated(
        epoch: u64,
        proposal_digest: [u8; 32],
        signed_envelope_digest: [u8; 32],
        lease: LeaseBounds,
        commit_index: u64,
        state_root: StateRoot,
    ) -> Self {
        Self {
            epoch,
            proposal_digest,
            signed_envelope_digest,
            lease,
            commit_index,
            state_root,
        }
    }
}

/// Audit record persisted before an activated gate is considered recoverable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivationReceipt {
    epoch: u64,
    holder: String,
    incarnation: u64,
    promotion_digest: [u8; 32],
    activated_at_ms: u64,
    expires_at_ms: u64,
}

impl ActivationReceipt {
    /// Creates an activation receipt bound to a promotion and process life.
    pub fn new(
        epoch: u64,
        holder: impl Into<String>,
        incarnation: u64,
        promotion_digest: [u8; 32],
        activated_at_ms: u64,
        expires_at_ms: u64,
    ) -> Result<Self, ModelError> {
        if epoch == 0 {
            return Err(ModelError::ZeroEpoch);
        }
        if incarnation == 0 {
            return Err(ModelError::ZeroIncarnation);
        }
        if activated_at_ms >= expires_at_ms {
            return Err(ModelError::InvalidActivationTime);
        }
        Ok(Self {
            epoch,
            holder: validate_identifier(holder.into())?,
            incarnation,
            promotion_digest,
            activated_at_ms,
            expires_at_ms,
        })
    }

    /// Activated epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Node for which effects were activated.
    #[must_use]
    pub fn holder(&self) -> &str {
        &self.holder
    }

    /// Holder boot generation.
    #[must_use]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Final candidate-signed envelope digest authorized for activation.
    #[must_use]
    pub const fn promotion_digest(&self) -> &[u8; 32] {
        &self.promotion_digest
    }

    /// Local activation time.
    #[must_use]
    pub const fn activated_at_ms(&self) -> u64 {
        self.activated_at_ms
    }

    /// Exclusive activation expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub(crate) fn from_validated(
        epoch: u64,
        holder: String,
        incarnation: u64,
        promotion_digest: [u8; 32],
        activated_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            epoch,
            holder,
            incarnation,
            promotion_digest,
            activated_at_ms,
            expires_at_ms,
        }
    }
}

/// Entire durable anti-replay and activation state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuthorityState {
    pub(crate) highest_epoch: u64,
    pub(crate) incarnation: u64,
    pub(crate) last_vote: Option<VoteRecord>,
    pub(crate) last_promotion: Option<PromotionRecord>,
    pub(crate) commit_index: u64,
    pub(crate) state_root: Option<StateRoot>,
    pub(crate) activation_receipt: Option<ActivationReceipt>,
}

impl AuthorityState {
    /// Highest epoch ever durably accepted or voted in.
    #[must_use]
    pub const fn highest_epoch(&self) -> u64 {
        self.highest_epoch
    }

    /// Highest allocated durable process incarnation.
    #[must_use]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Most recent durable vote.
    #[must_use]
    pub const fn last_vote(&self) -> Option<&VoteRecord> {
        self.last_vote.as_ref()
    }

    /// Most recent durable promotion envelope.
    #[must_use]
    pub const fn last_promotion(&self) -> Option<&PromotionRecord> {
        self.last_promotion.as_ref()
    }

    /// Latest durable workload commit.
    #[must_use]
    pub const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    /// State root corresponding exactly to `commit_index`.
    #[must_use]
    pub const fn state_root(&self) -> Option<StateRoot> {
        self.state_root
    }

    /// Most recent durable activation audit record.
    #[must_use]
    pub const fn activation_receipt(&self) -> Option<&ActivationReceipt> {
        self.activation_receipt.as_ref()
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if self.commit_index > 0 && self.state_root.is_none() {
            return Err(ModelError::MissingStateRoot);
        }
        if let Some(vote) = &self.last_vote {
            validate_identifier(vote.candidate.clone())?;
            if vote.epoch == 0 || vote.epoch > self.highest_epoch {
                return Err(ModelError::InvalidState);
            }
        }
        if let Some(promotion) = &self.last_promotion {
            let Some(vote) = &self.last_vote else {
                return Err(ModelError::InvalidState);
            };
            if promotion.epoch == 0
                || promotion.epoch > self.highest_epoch
                || vote.epoch != promotion.epoch
                || vote.proposal_digest != promotion.proposal_digest
                || promotion.lease.not_before_ms >= promotion.lease.expires_at_ms
                || promotion.commit_index > self.commit_index
            {
                return Err(ModelError::InvalidState);
            }
            if promotion.commit_index == self.commit_index
                && self.state_root != Some(promotion.state_root)
            {
                return Err(ModelError::InvalidState);
            }
        }
        if let Some(receipt) = &self.activation_receipt {
            validate_identifier(receipt.holder.clone())?;
            let Some(promotion) = &self.last_promotion else {
                return Err(ModelError::InvalidState);
            };
            let Some(vote) = &self.last_vote else {
                return Err(ModelError::InvalidState);
            };
            if receipt.epoch != promotion.epoch
                || receipt.epoch != self.highest_epoch
                || vote.epoch != receipt.epoch
                || vote.candidate != receipt.holder
                || vote.proposal_digest != promotion.proposal_digest
                || receipt.incarnation != self.incarnation
                || receipt.promotion_digest != promotion.signed_envelope_digest
                || receipt.activated_at_ms < promotion.lease.not_before_ms
                || receipt.expires_at_ms != promotion.lease.expires_at_ms
                || receipt.activated_at_ms >= receipt.expires_at_ms
            {
                return Err(ModelError::InvalidState);
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_identifier(value: String) -> Result<String, ModelError> {
    if value.is_empty() {
        return Err(ModelError::EmptyIdentifier);
    }
    if value.len() > 128 {
        return Err(ModelError::IdentifierTooLong);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ModelError::InvalidIdentifierCharacter);
    }
    Ok(value)
}

/// Invalid authority model input or recovered invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// Epoch zero is a sentinel and cannot carry authority.
    ZeroEpoch,
    /// Incarnation zero is a sentinel and cannot activate effects.
    ZeroIncarnation,
    /// Lease start is not strictly before its exclusive expiry.
    InvalidLease,
    /// Activation time is not strictly before its expiry.
    InvalidActivationTime,
    /// Node identifier is empty.
    EmptyIdentifier,
    /// Node identifier exceeds the canonical bound.
    IdentifierTooLong,
    /// Node identifier contains a byte outside the canonical alphabet.
    InvalidIdentifierCharacter,
    /// Store-instance identifier used the all-zero sentinel.
    ZeroStoreId,
    /// Non-zero commit progress has no corresponding state root.
    MissingStateRoot,
    /// Recovered or constructed state fields contradict one another.
    InvalidState,
}

impl Display for ModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroEpoch => formatter.write_str("epoch zero is reserved"),
            Self::ZeroIncarnation => formatter.write_str("incarnation zero is reserved"),
            Self::InvalidLease => formatter.write_str("lease bounds are empty or reversed"),
            Self::InvalidActivationTime => {
                formatter.write_str("activation time is outside its expiry")
            }
            Self::EmptyIdentifier => formatter.write_str("identifier is empty"),
            Self::IdentifierTooLong => formatter.write_str("identifier exceeds 128 bytes"),
            Self::InvalidIdentifierCharacter => {
                formatter.write_str("identifier contains a non-canonical character")
            }
            Self::ZeroStoreId => formatter.write_str("store identifier is the zero sentinel"),
            Self::MissingStateRoot => formatter.write_str("commit progress has no state root"),
            Self::InvalidState => {
                formatter.write_str("authority state invariants are inconsistent")
            }
        }
    }
}

impl Error for ModelError {}
