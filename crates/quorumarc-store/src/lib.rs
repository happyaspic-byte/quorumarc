//! Fail-closed durable authority storage for QuorumArc.
//!
//! The store writes one deterministic, checksummed snapshot frame to an
//! append-style journal filename. A transition is acknowledged only after a
//! temporary file is fully written, the file is synchronised, it is atomically
//! renamed over the committed frame, and the parent directory is synchronised
//! on platforms that support directory synchronisation.
//!
//! This crate provides local crash durability and anti-replay state. It is not
//! a consensus system, a quorum implementation, or proof of physical fencing.

mod backend;
mod codec;
mod model;
mod store;

pub use backend::{
    FaultInjectingBackend, FaultMode, FaultOperation, FaultRule, FileBackend, StorageBackend,
};
pub use codec::Corruption;
pub use model::{
    ActivationReceipt, AuthorityState, LeaseBounds, ModelError, PromotionRecord, StateRoot,
    VoteRecord,
};
pub use store::{
    DurabilityReceipt, DurableAuthorityStore, StoreError, StorePaths, TransitionOutcome,
};
