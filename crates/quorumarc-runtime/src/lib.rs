//! Fail-closed Gate 1A lab runtime primitives.
//!
//! This crate deliberately implements only a narrow integration increment:
//! a witness actor that durably records its binding before returning a signed
//! vote, a bounded length-prefixed stream frame, and an in-memory effect sink
//! that cannot bypass [`quorumarc_core::EffectGate`]. It is not a consensus
//! service, a production lease clock, a fencing implementation, or a complete
//! network protocol.

#![forbid(unsafe_code)]

mod effect;
mod frame;
mod witness;

pub use effect::{
    EffectEmitError, EffectOutcome, EffectReasonCode, TestEffectActor, TestEffectRecord,
    MAX_TEST_EFFECT_SIZE,
};
pub use frame::{
    FrameCodec, FrameConfigError, FrameError, FrameReasonCode, HARD_MAX_FRAME_SIZE,
};
pub use witness::{
    VoteReasonCode, VoteReply, WitnessOpenError, WitnessOpenReasonCode, WitnessPolicy,
    WitnessPolicyError, WitnessVoteActor,
};
