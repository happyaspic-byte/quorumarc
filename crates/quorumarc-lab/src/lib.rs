//! Reproducible, fail-closed localhost process lab for Gate 1A.0.
//!
//! This crate exercises real bounded TCP streams and the durable witness actor.
//! It does **not** implement consensus, fencing, workload failover, TLS, or an
//! authority-granting candidate. A witness response is evidence for a later
//! promotion proof; receiving one never opens an EffectGate.
//!
//! The built-in identities and keys are public deterministic **test fixtures**.
//! They authenticate protocol paths in CI, not real peers.

#![forbid(unsafe_code)]

mod fixture;
mod protocol;
mod service;

pub use fixture::{
    FixtureError, TEST_KEY_ID, TEST_POLICY_HASH, TEST_STATE_ROOT, TestPeerKeys, lab_binding,
    lab_policy, lab_witness_signing_key,
};
pub use protocol::{
    DecisionCode, MAX_LAB_FRAME_SIZE, PeerKeyResolver, ProtocolError, RequestId, VoteProof,
    VoteRequest, VoteResponse,
};
pub use service::{
    ClientError, ServeError, WitnessServerConfig, probe_loopback, request_vote, serve_witness,
};
