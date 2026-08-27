use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::management_journal::{JournalError, ManagementJournal, ManagementOutcome};
use crate::protocol::{AdmissionError, AuthenticatedRequestJournal};

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

/// Restarts from a durable request journal without opening effects.
#[derive(Debug)]
pub struct DurableController {
    admission: AuthenticatedRequestJournal,
    switch: PlannedSwitch,
}

impl DurableController {
    pub fn open(
        directory: &Path,
        identity: [u8; 16],
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
        from: SwitchRole,
        to: SwitchRole,
    ) -> Result<Self, JournalError> {
        let journal = ManagementJournal::open(directory, identity)?;
        Ok(Self {
            admission: AuthenticatedRequestJournal::new(journal, node_id, key_id, verifying_key),
            switch: PlannedSwitch::new(from, to),
        })
    }

    pub fn accept(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        self.admission.admit(bytes)
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.admission.highest_sequence()
    }

    #[must_use]
    pub const fn effects_open(&self) -> bool {
        self.switch.effects_open()
    }
}
