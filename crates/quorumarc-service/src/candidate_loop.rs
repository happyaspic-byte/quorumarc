use std::time::Duration;

use quorumarc_wire::ProductionQuorumCertificate;

use crate::operations::StatusHandle;
use crate::protocol::ProductionRequest;
use crate::signal::ShutdownToken;
use crate::witness_client::{
    CandidateControlError, ProductionCandidateControl, WitnessClientError,
};

const RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateFailure {
    NodeFailureSuspicion,
    Malformed,
    AuthenticationFailed,
    InvalidConfiguration,
}

impl CandidateFailure {
    const fn is_node_failure_suspicion(self) -> bool {
        matches!(self, Self::NodeFailureSuspicion)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateControlState {
    EffectClosed,
    SuspicionEffectClosed,
    CertifiedEffectClosed,
    StoppedEffectClosed,
}

impl CandidateControlState {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EffectClosed => "effect-closed",
            Self::SuspicionEffectClosed => "suspected/effect-closed",
            Self::CertifiedEffectClosed => "certified/effect-closed",
            Self::StoppedEffectClosed => "stopped/effect-closed",
        }
    }
}

pub trait CandidateAttempt {
    fn request_certificate(
        &mut self,
        request: ProductionRequest,
    ) -> Result<ProductionQuorumCertificate, CandidateControlError>;
}

impl CandidateAttempt for ProductionCandidateControl {
    fn request_certificate(
        &mut self,
        request: ProductionRequest,
    ) -> Result<ProductionQuorumCertificate, CandidateControlError> {
        ProductionCandidateControl::request_certificate(self, request)
    }
}

#[derive(Debug)]
pub struct CandidateControlLoop<C> {
    control: C,
    state: CandidateControlState,
    status: Option<StatusHandle>,
}

impl<C> CandidateControlLoop<C>
where
    C: CandidateAttempt,
{
    pub const MAX_ATTEMPTS: usize = 3;

    #[must_use]
    pub const fn new(control: C) -> Self {
        Self {
            control,
            state: CandidateControlState::EffectClosed,
            status: None,
        }
    }

    #[must_use]
    pub fn with_status(control: C, status: StatusHandle) -> Self {
        Self {
            control,
            state: CandidateControlState::EffectClosed,
            status: Some(status),
        }
    }

    #[must_use]
    pub const fn state(&self) -> CandidateControlState {
        self.state
    }

    #[must_use]
    pub const fn state_label(&self) -> &'static str {
        self.state.label()
    }

    #[must_use]
    pub const fn effect_gate_state(&self) -> &'static str {
        "closed"
    }

    pub fn handle(
        &mut self,
        failure: CandidateFailure,
        request: ProductionRequest,
    ) -> CandidateControlState {
        if !failure.is_node_failure_suspicion() {
            self.transition(CandidateControlState::EffectClosed);
            return self.state;
        }
        self.transition(CandidateControlState::SuspicionEffectClosed);
        let result = self.control.request_certificate(request);
        self.apply_result(result)
    }

    pub fn run_bounded(
        &mut self,
        failure: CandidateFailure,
        request: ProductionRequest,
        shutdown: &ShutdownToken,
    ) -> CandidateControlState {
        if shutdown.is_requested() {
            self.transition(CandidateControlState::StoppedEffectClosed);
            return self.state;
        }
        if !failure.is_node_failure_suspicion() {
            self.transition(CandidateControlState::EffectClosed);
            return self.state;
        }
        self.transition(CandidateControlState::SuspicionEffectClosed);
        for attempt in 0..Self::MAX_ATTEMPTS {
            if shutdown.is_requested() {
                self.transition(CandidateControlState::StoppedEffectClosed);
                return self.state;
            }
            let result = self.control.request_certificate(request.clone());
            let retry = matches!(
                &result,
                Err(CandidateControlError::Witness(
                    WitnessClientError::Transport
                ))
            );
            let state = self.apply_result(result);
            if !retry || attempt.saturating_add(1) >= Self::MAX_ATTEMPTS {
                return state;
            }
            shutdown.wait_timeout(RETRY_DELAY);
        }
        self.state
    }

    pub fn wait_until_shutdown(&mut self, shutdown: &ShutdownToken) {
        if !shutdown.is_requested() {
            shutdown.wait();
        }
        self.transition(CandidateControlState::StoppedEffectClosed);
    }

    pub fn control_mut(&mut self) -> &mut C {
        &mut self.control
    }

    fn apply_result(
        &mut self,
        result: Result<ProductionQuorumCertificate, CandidateControlError>,
    ) -> CandidateControlState {
        match result {
            Ok(_certificate) => self.transition(CandidateControlState::CertifiedEffectClosed),
            Err(error) if error.is_node_failure_suspicion() => {
                self.transition(CandidateControlState::SuspicionEffectClosed)
            }
            Err(_error) => self.transition(CandidateControlState::EffectClosed),
        }
        self.state
    }

    fn transition(&mut self, state: CandidateControlState) {
        self.state = state;
        if let Some(status) = &self.status {
            let _ = status.set_candidate_control_state(state.label());
        }
    }
}
