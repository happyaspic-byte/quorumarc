//! Small, dependency-free safety primitives for QuorumArc Gate 0.
//!
//! This crate deliberately does not perform consensus, persistence, networking,
//! clock synchronisation, cryptographic signing, or real fencing. It validates
//! typed evidence and ensures the local effect gate fails closed.

mod gate;
mod proof;
mod types;

pub use gate::{
    ContinuityReceipt, EffectGate, GateError, GatePersistenceRecord, GateRecoveryState, GateState,
    SelfFenceReason, TrustedClock,
};
pub use proof::{
    AuthorityState, FenceClass, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant,
    PolicyError, PromotionProof, ProofError, QuorumCertificate, SafetyPolicy, StateEvidence,
    ValidatedPromotion, validate_promotion,
};
pub use types::{
    CommitIndex, Epoch, IdError, Incarnation, NodeId, PolicyHash, StateRoot, WorkloadId,
};
