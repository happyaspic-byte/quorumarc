//! Fail-closed production service foundation for QuorumArc Gate 1.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

pub mod adapters;
pub mod clock;
pub mod config;
pub mod controller;
pub mod management_journal;
pub mod metrics;
pub mod node;
pub mod operations;
pub mod protocol;
pub mod reload;
pub mod signal;
pub mod tls;
pub mod watchdog;
pub mod witness;
