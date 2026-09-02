use crate::adapters::{AdapterError, CloseReason, ClosedOnlyEffectAdapter, EffectAdapter};
use crate::signal::ShutdownToken;

/// Production node daemon holding an active fail-closed effect adapter.
#[derive(Debug)]
pub struct ProductionNode<A = ClosedOnlyEffectAdapter> {
    readiness: DaemonReadiness,
    adapter: A,
}

/// Observable daemon readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonReadiness {
    EffectClosed,
    Stopped,
}

/// One bounded daemon-run report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonReport {
    pub initial: DaemonReadiness,
    pub final_state: DaemonReadiness,
    pub ever_ready: bool,
}

impl Default for ProductionNode<ClosedOnlyEffectAdapter> {
    fn default() -> Self {
        Self::effect_closed()
    }
}

impl ProductionNode<ClosedOnlyEffectAdapter> {
    /// Constructs a node whose EffectGate remains closed.
    #[must_use]
    pub const fn effect_closed() -> Self {
        Self {
            readiness: DaemonReadiness::EffectClosed,
            adapter: ClosedOnlyEffectAdapter,
        }
    }
}

impl<A: EffectAdapter> ProductionNode<A> {
    /// Starts only when the bound adapter is independently verified closed.
    pub fn from_effect_adapter(adapter: A) -> Result<Self, AdapterError> {
        adapter.verify_closed()?;
        Ok(Self {
            readiness: DaemonReadiness::EffectClosed,
            adapter,
        })
    }

    /// Current readiness.
    #[must_use]
    pub const fn readiness(&self) -> DaemonReadiness {
        self.readiness
    }

    /// Access to the underlying effect adapter.
    #[must_use]
    pub const fn adapter(&self) -> &A {
        &self.adapter
    }

    /// Runs the closed-gate daemon loop until shutdown, then closes and verifies the adapter.
    pub fn run_until_shutdown(
        &mut self,
        shutdown: &ShutdownToken,
    ) -> Result<DaemonReport, AdapterError> {
        let initial = self.readiness;
        if !shutdown.is_requested() {
            shutdown.wait();
        }
        self.adapter.close(CloseReason::ExplicitClose)?;
        self.adapter.verify_closed()?;
        self.readiness = DaemonReadiness::Stopped;
        Ok(DaemonReport {
            initial,
            final_state: self.readiness,
            ever_ready: false,
        })
    }

    /// External-effect state.
    #[must_use]
    pub const fn effect_gate_state(&self) -> &'static str {
        "closed"
    }

    /// Authority remains denied until later milestones.
    #[must_use]
    pub const fn authority_enabled(&self) -> bool {
        false
    }
}
