use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};

use crate::backend::StorageBackend;
use crate::codec::{Corruption, decode, encode};
use crate::model::{
    ActivationReceipt, AuthorityState, ModelError, PromotionRecord, StateRoot, VoteRecord,
};

/// Fixed paths used for an authority snapshot journal and its staging file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StorePaths {
    directory: PathBuf,
    committed: PathBuf,
    temporary: PathBuf,
}

impl StorePaths {
    /// Creates paths below an authority-store directory.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        let committed = directory.join("authority.journal");
        let temporary = directory.join("authority.journal.tmp");
        Self {
            directory,
            committed,
            temporary,
        }
    }

    /// Store directory whose metadata is synchronised after rename.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Committed durable frame.
    #[must_use]
    pub fn committed(&self) -> &Path {
        &self.committed
    }

    /// Non-authoritative staging file.
    #[must_use]
    pub fn temporary(&self) -> &Path {
        &self.temporary
    }
}

/// Whether a store transition wrote a new durable generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    /// A new frame was fully committed and synchronised.
    Committed,
    /// The exact requested state was already known durable.
    AlreadyDurable,
}

/// Non-forgeable acknowledgement issued only for known durable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurabilityReceipt {
    generation: u64,
    outcome: TransitionOutcome,
}

impl DurabilityReceipt {
    /// Durable frame generation containing the acknowledged transition.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Whether this call committed a frame or observed an idempotent one.
    #[must_use]
    pub const fn outcome(self) -> TransitionOutcome {
        self.outcome
    }
}

/// Fail-closed local durable authority store.
pub struct DurableAuthorityStore<B> {
    backend: B,
    paths: StorePaths,
    state: AuthorityState,
    generation: u64,
    poisoned: bool,
}

impl<B: StorageBackend> DurableAuthorityStore<B> {
    /// Recovers a store, rejecting any corrupt, truncated, or inconsistent
    /// committed frame. A stale temporary frame never grants authority.
    pub fn open(paths: StorePaths, mut backend: B) -> Result<Self, StoreError> {
        backend
            .create_dir_all(paths.directory())
            .map_err(|error| StoreError::io("create store directory", error))?;
        let recovered = backend
            .read_file(paths.committed())
            .map_err(|error| StoreError::io("read committed authority frame", error))?;
        let (state, generation) = match recovered {
            Some(bytes) => decode(&bytes).map_err(StoreError::Corrupt)?,
            None => (AuthorityState::default(), 0),
        };
        backend
            .remove_file_if_exists(paths.temporary())
            .map_err(|error| StoreError::io("remove stale authority staging file", error))?;
        Ok(Self {
            backend,
            paths,
            state,
            generation,
            poisoned: false,
        })
    }

    /// Opens a store in `directory` using the standard filenames.
    pub fn open_in(directory: impl Into<PathBuf>, backend: B) -> Result<Self, StoreError> {
        Self::open(StorePaths::new(directory), backend)
    }

    /// Exact state recovered from or committed to durable storage.
    #[must_use]
    pub const fn state(&self) -> &AuthorityState {
        &self.state
    }

    /// Current durable frame generation, or zero for a fresh empty store.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether a durability operation failed and further writes are blocked.
    #[must_use]
    pub const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Files controlled by this store.
    #[must_use]
    pub const fn paths(&self) -> &StorePaths {
        &self.paths
    }

    /// Returns the backend, primarily for deterministic test inspection.
    #[must_use]
    pub fn into_backend(self) -> B {
        self.backend
    }

    /// Durably allocates a strictly newer process incarnation.
    pub fn allocate_incarnation(
        &mut self,
        incarnation: u64,
    ) -> Result<DurabilityReceipt, StoreError> {
        self.ensure_writable()?;
        if incarnation == 0 || incarnation <= self.state.incarnation {
            return Err(StoreError::StaleIncarnation {
                requested: incarnation,
                durable: self.state.incarnation,
            });
        }
        let mut next = self.state.clone();
        next.incarnation = incarnation;
        next.activation_receipt = None;
        self.persist(next)
    }

    /// Persists a vote before it is emitted. An exact retry is idempotent;
    /// another vote in the same epoch is rejected as a double vote.
    pub fn record_vote(&mut self, vote: VoteRecord) -> Result<DurabilityReceipt, StoreError> {
        self.ensure_writable()?;
        if vote.epoch() < self.state.highest_epoch {
            return Err(StoreError::StaleEpoch {
                requested: vote.epoch(),
                durable: self.state.highest_epoch,
            });
        }
        if let Some(existing) = &self.state.last_vote {
            if existing.epoch() == vote.epoch() {
                if existing == &vote {
                    return Ok(self.already_durable());
                }
                return Err(StoreError::DoubleVote {
                    epoch: vote.epoch(),
                });
            }
        }
        if vote.epoch() == self.state.highest_epoch {
            return Err(StoreError::EpochAlreadyAccepted {
                epoch: vote.epoch(),
            });
        }

        let mut next = self.state.clone();
        next.highest_epoch = vote.epoch();
        next.last_vote = Some(vote);
        next.last_promotion = None;
        next.activation_receipt = None;
        self.persist(next)
    }

    /// Persists a promotion bound to the matching durable vote. Commit progress
    /// may advance but may never regress or change root at the same index.
    pub fn record_promotion(
        &mut self,
        promotion: PromotionRecord,
    ) -> Result<DurabilityReceipt, StoreError> {
        self.ensure_writable()?;
        if promotion.epoch() < self.state.highest_epoch {
            return Err(StoreError::StaleEpoch {
                requested: promotion.epoch(),
                durable: self.state.highest_epoch,
            });
        }
        if let Some(existing) = &self.state.last_promotion {
            if existing.epoch() == promotion.epoch() {
                if existing == &promotion {
                    return Ok(self.already_durable());
                }
                return Err(StoreError::ConflictingPromotion {
                    epoch: promotion.epoch(),
                });
            }
        }
        let Some(vote) = &self.state.last_vote else {
            return Err(StoreError::MissingVote {
                epoch: promotion.epoch(),
            });
        };
        if vote.epoch() != promotion.epoch() {
            return Err(StoreError::MissingVote {
                epoch: promotion.epoch(),
            });
        }
        if vote.proposal_digest() != promotion.digest() {
            return Err(StoreError::VoteDigestMismatch {
                epoch: promotion.epoch(),
            });
        }
        self.validate_progress(promotion.commit_index(), promotion.state_root())?;

        let mut next = self.state.clone();
        next.highest_epoch = promotion.epoch();
        next.commit_index = promotion.commit_index();
        next.state_root = Some(promotion.state_root());
        next.last_promotion = Some(promotion);
        next.activation_receipt = None;
        self.persist(next)
    }

    /// Advances durable workload progress without changing authority.
    pub fn record_progress(
        &mut self,
        commit_index: u64,
        state_root: StateRoot,
    ) -> Result<DurabilityReceipt, StoreError> {
        self.ensure_writable()?;
        self.validate_progress(commit_index, state_root)?;
        if commit_index == self.state.commit_index && self.state.state_root == Some(state_root) {
            return Ok(self.already_durable());
        }
        let mut next = self.state.clone();
        next.commit_index = commit_index;
        next.state_root = Some(state_root);
        self.persist(next)
    }

    /// Persists an activation audit record that exactly matches the current
    /// promotion, vote candidate, incarnation, and lease.
    pub fn record_activation(
        &mut self,
        receipt: ActivationReceipt,
    ) -> Result<DurabilityReceipt, StoreError> {
        self.ensure_writable()?;
        if let Some(existing) = &self.state.activation_receipt {
            if existing == &receipt {
                return Ok(self.already_durable());
            }
            if existing.epoch() == receipt.epoch() {
                return Err(StoreError::ConflictingActivation {
                    epoch: receipt.epoch(),
                });
            }
        }
        let Some(promotion) = &self.state.last_promotion else {
            return Err(StoreError::ActivationMismatch);
        };
        let Some(vote) = &self.state.last_vote else {
            return Err(StoreError::ActivationMismatch);
        };
        if receipt.epoch() != self.state.highest_epoch
            || receipt.epoch() != promotion.epoch()
            || receipt.holder() != vote.candidate()
            || receipt.incarnation() != self.state.incarnation
            || receipt.promotion_digest() != promotion.digest()
            || receipt.activated_at_ms() < promotion.lease().not_before_ms()
            || receipt.expires_at_ms() != promotion.lease().expires_at_ms()
        {
            return Err(StoreError::ActivationMismatch);
        }
        let mut next = self.state.clone();
        next.activation_receipt = Some(receipt);
        self.persist(next)
    }

    fn validate_progress(
        &self,
        commit_index: u64,
        state_root: StateRoot,
    ) -> Result<(), StoreError> {
        if commit_index < self.state.commit_index {
            return Err(StoreError::CommitRegression {
                requested: commit_index,
                durable: self.state.commit_index,
            });
        }
        if commit_index == self.state.commit_index
            && self.state.state_root.is_some()
            && self.state.state_root != Some(state_root)
        {
            return Err(StoreError::StateRootConflict { commit_index });
        }
        Ok(())
    }

    fn ensure_writable(&self) -> Result<(), StoreError> {
        if self.poisoned {
            return Err(StoreError::Poisoned);
        }
        Ok(())
    }

    const fn already_durable(&self) -> DurabilityReceipt {
        DurabilityReceipt {
            generation: self.generation,
            outcome: TransitionOutcome::AlreadyDurable,
        }
    }

    fn persist(&mut self, next: AuthorityState) -> Result<DurabilityReceipt, StoreError> {
        next.validate().map_err(StoreError::InvalidInput)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(StoreError::GenerationExhausted)?;
        let bytes = encode(&next, generation);

        if let Err(error) = self.backend.remove_file_if_exists(self.paths.temporary()) {
            return self.fail("prepare authority staging file", error);
        }
        if let Err(error) = self.backend.write_file(self.paths.temporary(), &bytes) {
            return self.fail_and_clean("write authority staging file", error);
        }
        if let Err(error) = self.backend.sync_file(self.paths.temporary()) {
            return self.fail_and_clean("synchronise authority staging file", error);
        }
        if let Err(error) = self
            .backend
            .rename(self.paths.temporary(), self.paths.committed())
        {
            return self.fail_and_clean("rename committed authority frame", error);
        }
        match self.backend.sync_directory(self.paths.directory()) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {}
            Err(error) => return self.fail("synchronise authority directory", error),
        }

        self.state = next;
        self.generation = generation;
        Ok(DurabilityReceipt {
            generation,
            outcome: TransitionOutcome::Committed,
        })
    }

    fn fail<T>(&mut self, operation: &'static str, error: io::Error) -> Result<T, StoreError> {
        self.poisoned = true;
        Err(StoreError::io(operation, error))
    }

    fn fail_and_clean<T>(
        &mut self,
        operation: &'static str,
        error: io::Error,
    ) -> Result<T, StoreError> {
        let _cleanup_result = self.backend.remove_file_if_exists(self.paths.temporary());
        self.fail(operation, error)
    }
}

/// Authority-store recovery, transition, or durability failure.
#[derive(Debug)]
pub enum StoreError {
    /// A committed frame was malformed or damaged. No state is returned.
    Corrupt(Corruption),
    /// Filesystem durability operation failed.
    Io {
        /// Operation whose durability contract failed.
        operation: &'static str,
        /// Portable I/O error category.
        kind: io::ErrorKind,
        /// Backend error detail.
        message: String,
    },
    /// A previous write failed; reopen is required before another transition.
    Poisoned,
    /// Requested epoch is older than durable authority.
    StaleEpoch {
        /// Requested epoch.
        requested: u64,
        /// Highest durable epoch.
        durable: u64,
    },
    /// A different vote already exists for this epoch.
    DoubleVote {
        /// Conflicting epoch.
        epoch: u64,
    },
    /// The epoch was accepted through another transition and cannot be voted
    /// retroactively.
    EpochAlreadyAccepted {
        /// Already accepted epoch.
        epoch: u64,
    },
    /// No durable vote matches the promotion epoch.
    MissingVote {
        /// Promotion epoch.
        epoch: u64,
    },
    /// Promotion digest differs from the proposal bound into the durable vote.
    VoteDigestMismatch {
        /// Promotion epoch.
        epoch: u64,
    },
    /// Another promotion is already accepted for this epoch.
    ConflictingPromotion {
        /// Conflicting epoch.
        epoch: u64,
    },
    /// Requested incarnation is zero or not strictly newer.
    StaleIncarnation {
        /// Requested incarnation.
        requested: u64,
        /// Durable incarnation.
        durable: u64,
    },
    /// Workload progress attempted to move backward.
    CommitRegression {
        /// Requested commit.
        requested: u64,
        /// Durable commit.
        durable: u64,
    },
    /// Same commit index was supplied with another state root.
    StateRootConflict {
        /// Conflicting commit index.
        commit_index: u64,
    },
    /// Activation did not exactly match durable promotion authority.
    ActivationMismatch,
    /// A different activation receipt already exists at this epoch.
    ConflictingActivation {
        /// Conflicting epoch.
        epoch: u64,
    },
    /// Input or resulting state violated model invariants.
    InvalidInput(ModelError),
    /// Durable frame generation cannot be incremented.
    GenerationExhausted,
}

impl StoreError {
    fn io(operation: &'static str, error: io::Error) -> Self {
        Self::Io {
            operation,
            kind: error.kind(),
            message: error.to_string(),
        }
    }
}

impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Corrupt(error) => write!(formatter, "authority recovery refused: {error}"),
            Self::Io {
                operation,
                kind,
                message,
            } => write!(formatter, "{operation} failed ({kind:?}): {message}"),
            Self::Poisoned => formatter.write_str(
                "authority store is fail-closed after a durability failure; reopen is required",
            ),
            Self::StaleEpoch { requested, durable } => write!(
                formatter,
                "epoch {requested} is stale; highest durable epoch is {durable}"
            ),
            Self::DoubleVote { epoch } => {
                write!(
                    formatter,
                    "a different durable vote already exists at epoch {epoch}"
                )
            }
            Self::EpochAlreadyAccepted { epoch } => write!(
                formatter,
                "epoch {epoch} was already accepted and cannot be voted retroactively"
            ),
            Self::MissingVote { epoch } => {
                write!(
                    formatter,
                    "no matching durable vote exists for epoch {epoch}"
                )
            }
            Self::VoteDigestMismatch { epoch } => write!(
                formatter,
                "promotion digest does not match the durable vote at epoch {epoch}"
            ),
            Self::ConflictingPromotion { epoch } => write!(
                formatter,
                "a different durable promotion already exists at epoch {epoch}"
            ),
            Self::StaleIncarnation { requested, durable } => write!(
                formatter,
                "incarnation {requested} is not newer than durable incarnation {durable}"
            ),
            Self::CommitRegression { requested, durable } => write!(
                formatter,
                "commit {requested} regresses from durable commit {durable}"
            ),
            Self::StateRootConflict { commit_index } => write!(
                formatter,
                "state root conflicts at durable commit {commit_index}"
            ),
            Self::ActivationMismatch => {
                formatter.write_str("activation does not match durable promotion authority")
            }
            Self::ConflictingActivation { epoch } => write!(
                formatter,
                "a different activation receipt already exists at epoch {epoch}"
            ),
            Self::InvalidInput(error) => write!(formatter, "invalid authority state: {error}"),
            Self::GenerationExhausted => {
                formatter.write_str("durable authority generation is exhausted")
            }
        }
    }
}

impl Error for StoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Corrupt(error) => Some(error),
            Self::InvalidInput(error) => Some(error),
            _ => None,
        }
    }
}
