/// One data-node role in a planned switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchRole {
    NodeA,
    NodeB,
}

/// Strict planned-switch transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedSwitchStep {
    Prepare,
    CatchUp,
    HealthVerify,
    Drain,
    CloseOldEffects,
    Certify,
    PersistActivation,
    OpenNewEffects,
    Receipt,
    Complete,
    Halted,
}

/// Planned-switch refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedSwitchError {
    Ambiguous,
    SameRole,
}

/// Fail-closed planned switch state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedSwitch {
    from: SwitchRole,
    to: SwitchRole,
    step: PlannedSwitchStep,
    effects_open: bool,
}

impl PlannedSwitch {
    /// Starts a switch with both external-effect paths considered closed.
    #[must_use]
    pub const fn new(from: SwitchRole, to: SwitchRole) -> Self {
        Self {
            from,
            to,
            step: PlannedSwitchStep::Prepare,
            effects_open: false,
        }
    }

    /// Current durable transaction step.
    #[must_use]
    pub const fn step(&self) -> PlannedSwitchStep {
        self.step
    }

    /// Whether the new effect path was reached.
    #[must_use]
    pub const fn effects_open(&self) -> bool {
        self.effects_open
    }

    /// Advances exactly one expected step; ambiguity halts closed.
    pub fn advance(&mut self, requested: PlannedSwitchStep) -> Result<(), PlannedSwitchError> {
        if self.from == self.to {
            self.halt();
            return Err(PlannedSwitchError::SameRole);
        }
        let Some(expected) = next_step(self.step) else {
            self.halt();
            return Err(PlannedSwitchError::Ambiguous);
        };
        if requested != expected {
            self.halt();
            return Err(PlannedSwitchError::Ambiguous);
        }
        self.step = if requested == PlannedSwitchStep::Receipt {
            PlannedSwitchStep::Complete
        } else {
            requested
        };
        if requested == PlannedSwitchStep::OpenNewEffects || requested == PlannedSwitchStep::Receipt
        {
            self.effects_open = true;
        }
        Ok(())
    }

    fn halt(&mut self) {
        self.effects_open = false;
        self.step = PlannedSwitchStep::Halted;
    }
}

const fn next_step(step: PlannedSwitchStep) -> Option<PlannedSwitchStep> {
    match step {
        PlannedSwitchStep::Prepare => Some(PlannedSwitchStep::CatchUp),
        PlannedSwitchStep::CatchUp => Some(PlannedSwitchStep::HealthVerify),
        PlannedSwitchStep::HealthVerify => Some(PlannedSwitchStep::Drain),
        PlannedSwitchStep::Drain => Some(PlannedSwitchStep::CloseOldEffects),
        PlannedSwitchStep::CloseOldEffects => Some(PlannedSwitchStep::Certify),
        PlannedSwitchStep::Certify => Some(PlannedSwitchStep::PersistActivation),
        PlannedSwitchStep::PersistActivation => Some(PlannedSwitchStep::OpenNewEffects),
        PlannedSwitchStep::OpenNewEffects => Some(PlannedSwitchStep::Receipt),
        PlannedSwitchStep::Receipt | PlannedSwitchStep::Complete | PlannedSwitchStep::Halted => {
            None
        }
    }
}
