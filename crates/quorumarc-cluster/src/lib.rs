//! Bounded, localhost-only three-process integrations.
//!
//! The one-shot path exercises one RPO-0 demonstration write and bootstrap
//! activation. The lifecycle path keeps identical Node A/B services and a
//! durable Witness alive across signed, lease-guarded authority transfers and
//! process faults. A separate bounded process executes automatic lab decisions,
//! but it is not a production controller, fence, trusted clock, or proof of
//! global uniqueness.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

mod auto_controller;
mod bootstrap;
mod continuous;
mod fault_proxy;
mod keys;
mod lifecycle;
mod path_guard;
mod peer;
mod protocol;
mod self_test;
mod witness;

use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub use auto_controller::{
    LifecycleControllerConfig, LifecycleControllerReport, run_lifecycle_controller,
};
pub use bootstrap::{BootstrapConfig, BootstrapReport, run_bootstrap};
pub use continuous::{
    ContinuousClient, ContinuousPrimaryConfig, ContinuousReplicaConfig, ContinuousSubmitOutcome,
    serve_continuous_primary, serve_continuous_replica,
};
pub use fault_proxy::{FaultProxyConfig, serve_fault_proxy};
pub use keys::{load_private_seed, load_public_key};
pub use lifecycle::{
    LifecycleAutoController, LifecycleAutoDecision, LifecycleAutoReason, LifecycleClient,
    LifecycleNodeConfig, LifecycleNodeId, LifecycleReasonCode, LifecycleReport, LifecycleState,
    LifecycleStoreFault, LifecycleWitnessConfig, lifecycle_lease, lifecycle_policy_hash,
    serve_lifecycle_node, serve_lifecycle_witness,
};
pub use peer::{PeerConfig, serve_peer};
pub use self_test::{SelfTestConfig, SelfTestReport, run_self_test};
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
