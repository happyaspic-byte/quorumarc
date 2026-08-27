/// Production node daemon that cannot open effects until later milestones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionNode {
    readiness: DaemonReadiness,
}

/// Observable daemon readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonReadiness {
    EffectClosed,
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
