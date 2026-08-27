//! Fail-closed production service foundation for QuorumArc Gate 1.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

pub mod clock;
pub mod config;
pub mod management_journal;
pub mod node;
pub mod signal;
pub mod witness;
