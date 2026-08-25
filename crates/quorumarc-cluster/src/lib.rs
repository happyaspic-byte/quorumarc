//! Bounded, localhost-only three-process integration named
//! `LAB_GENESIS_ONE_SHOT`.
//!
//! This crate exercises one RPO-0 demonstration write, one durable witness
//! vote, one canonical promotion proof, durable candidate authority state and
//! one gated test-sink effect. It is deliberately not a failover controller,
//! consensus implementation, production fence, production clock, or proof of
//! a globally unique genesis. The fixed clock and one-shot epoch are test
//! fixtures only.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

mod bootstrap;
mod keys;
mod path_guard;
mod peer;
mod protocol;
mod witness;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub use bootstrap::{BootstrapConfig, BootstrapReport, run_bootstrap};
pub use keys::{load_private_seed, load_public_key};
pub use peer::{PeerConfig, serve_peer};
pub use witness::{WitnessConfig, serve_witness};

/// Stable bounded-lab failure with a machine-readable refusal code.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClusterError {
    code: &'static str,
    detail: String,
}

impl ClusterError {
    /// Creates a typed refusal for CLI and integration boundaries.
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Machine-readable fail-closed reason.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.code
    }

    /// Diagnostic detail that does not carry authority.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl Display for ClusterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "code={} detail={}", self.code, self.detail)
    }
}

impl Error for ClusterError {}

pub(crate) fn err(code: &'static str, detail: impl Into<String>) -> ClusterError {
    ClusterError::new(code, detail)
}
