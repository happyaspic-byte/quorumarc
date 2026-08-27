use std::thread;
use std::time::Duration;

use crate::signal::ShutdownToken;

/// Production node daemon that cannot open effects until later milestones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionNode {
    readiness: DaemonReadiness,
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

impl ProductionNode {
    /// Constructs a node whose EffectGate remains closed.
    #[must_use]
    pub const fn effect_closed() -> Self {
        Self {
            readiness: DaemonReadiness::EffectClosed,
        }
    }

    /// Current readiness.
    #[must_use]
    pub const fn readiness(&self) -> DaemonReadiness {
        self.readiness
    }

    /// Runs the closed-gate daemon loop until shutdown.
    pub fn run_until_shutdown(
        &mut self,
        shutdown: &ShutdownToken,
        poll_interval: Duration,
    ) -> DaemonReport {
        let initial = self.readiness;
        while !shutdown.is_requested() {
            thread::sleep(poll_interval);
        }
        self.readiness = DaemonReadiness::Stopped;
        DaemonReport {
            initial,
            final_state: self.readiness,
            ever_ready: false,
        }
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
