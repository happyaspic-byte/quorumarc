use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::lifecycle::{
    LifecycleAutoController, LifecycleAutoDecision, LifecycleAutoReason, LifecycleClient,
    LifecycleNodeId, LifecycleReasonCode, lifecycle_lease,
};
use crate::path_guard::{prepare_file_parent, reject_symlink_components};
use crate::{ClusterError, err};

const MAX_PROMOTIONS: u64 = 16;
const MAX_LOGICAL_STEP_MS: u64 = 50;
const MAX_POLL_MS: u128 = 1_000;
const MAX_TIMEOUT_MS: u128 = 5_000;
const MAX_RUNTIME_MS: u128 = 60_000;

/// Settings for the bounded, localhost-only automatic lifecycle controller.
#[derive(Clone, Debug)]
pub struct LifecycleControllerConfig {
    pub node_a_address: SocketAddr,
    pub node_b_address: SocketAddr,
    pub node_a_public_key_file: PathBuf,
    pub node_b_public_key_file: PathBuf,
    pub controller_signing_key_file: PathBuf,
    pub trace_file: PathBuf,
    pub failure_threshold: u32,
    pub max_promotions: u64,
    pub logical_step_ms: u64,
    pub poll_interval: Duration,
    pub observation_timeout: Duration,
    pub authority_timeout: Duration,
    pub max_runtime: Duration,
    pub emit_test_effect: bool,
}

/// Final bounded-controller outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleControllerReport {
    pub promotions: u64,
    pub final_active: LifecycleNodeId,
    pub final_epoch: u64,
    pub final_effect_count: u64,
    pub elapsed_ms: u128,
    pub final_failure_detection_ms: u128,
    pub final_lease_wait_ms: u128,
    pub final_promotion_ms: u128,
    pub final_effect_ms: u128,
}

/// Runs authenticated observation and automatic promotion execution for the
/// shared-host lifecycle laboratory.
///
/// A missing report is only failure suspicion. The deterministic decision
/// machine still waits for the previous exclusive lease and guard, while the
/// selected node independently requires a durable Witness vote, complete
/// promotion proof, durable activation receipt, and EffectGate activation.
pub fn run_lifecycle_controller(
    config: LifecycleControllerConfig,
) -> Result<LifecycleControllerReport, ClusterError> {
    validate_config(&config)?;
    let node_a_key = load_public_key(&config.node_a_public_key_file)?;
    let node_b_key = load_public_key(&config.node_b_public_key_file)?;
    let controller_key = load_private_seed(&config.controller_signing_key_file)?;
    require_distinct_role_keys(&[
        (LifecycleNodeId::NodeA.as_str(), &node_a_key),
        (LifecycleNodeId::NodeB.as_str(), &node_b_key),
        ("lifecycle-controller", &controller_key.verifying_key()),
    ])?;

    let mut trace = ControllerTrace::create(&config.trace_file)?;
    trace.record(&format!(
        "event=controller_started failure_threshold={} max_promotions={} logical_step_ms={} observation_timeout_ms={} authority_timeout_ms={} emit_test_effect={}",
        config.failure_threshold,
        config.max_promotions,
        config.logical_step_ms,
        config.observation_timeout.as_millis(),
        config.authority_timeout.as_millis(),
        config.emit_test_effect
    ))?;
    let mut node_a = LifecycleClient::new(
        config.node_a_address,
        LifecycleNodeId::NodeA,
        node_a_key,
        controller_key.clone(),
        config.authority_timeout,
    );
    let mut node_b = LifecycleClient::new(
        config.node_b_address,
        LifecycleNodeId::NodeB,
        node_b_key,
        controller_key,
        config.authority_timeout,
    );
    let mut controller = LifecycleAutoController::new(config.failure_threshold)?;
    let (logical_start_ms, _) = lifecycle_lease(1)?;
    let started = Instant::now();
    let mut promotions = 0_u64;
    let mut last_observation_a = None;
    let mut last_observation_b = None;
    let mut last_decision = None;
    let mut failover_timing = FailoverTiming::default();

    loop {
        let elapsed = started.elapsed();
        if elapsed >= config.max_runtime {
            trace.record("event=controller_halt reason=MAX_RUNTIME_EXCEEDED")?;
            return Err(err(
                "LIFECYCLE_CONTROLLER_TIMEOUT",
                "bounded automatic controller exceeded max runtime",
            ));
        }
        let now_ms = controller_now_ms(logical_start_ms, elapsed, config.logical_step_ms)?;
        let observation_timeout = runtime_timeout(
            remaining_runtime(started, config.max_runtime),
            config.observation_timeout,
        )?;
        let observation_started_a = started.elapsed().as_millis();
        let report_a = observe(
            &mut node_a,
            now_ms,
            observation_timeout,
            &mut trace,
            LifecycleNodeId::NodeA,
            &mut last_observation_a,
        )?;
        failover_timing.record_observation(
            LifecycleNodeId::NodeA,
            report_a.as_ref(),
            observation_started_a,
        );
        let observation_timeout = runtime_timeout(
            remaining_runtime(started, config.max_runtime),
            config.observation_timeout,
        )?;
        let observation_started_b = started.elapsed().as_millis();
        let report_b = observe(
            &mut node_b,
            now_ms,
            observation_timeout,
            &mut trace,
            LifecycleNodeId::NodeB,
            &mut last_observation_b,
        )?;
        failover_timing.record_observation(
            LifecycleNodeId::NodeB,
            report_b.as_ref(),
            observation_started_b,
        );
        let elapsed_ms = started.elapsed().as_millis();
        let decision = controller.evaluate(now_ms, report_a.as_ref(), report_b.as_ref(), true)?;
        failover_timing.record_decision(decision, elapsed_ms);
        let decision_label = decision_label(decision);
        if last_decision.as_ref() != Some(&decision_label) {
            trace.record(&format!(
                "event=controller_decision now_ms={now_ms} decision={decision_label}"
            ))?;
            last_decision = Some(decision_label);
        }

        match decision {
            LifecycleAutoDecision::Promote { candidate, epoch } => {
                let promotion_timeout = runtime_timeout(
                    remaining_runtime(started, config.max_runtime),
                    config.authority_timeout,
                )?;
                let client = match candidate {
                    LifecycleNodeId::NodeA => &mut node_a,
                    LifecycleNodeId::NodeB => &mut node_b,
                };
                let promotion_started_ms = started.elapsed().as_millis();
                let stages = failover_timing.stages(promotion_started_ms);
                let promotion_started = Instant::now();
                let promotion = match client.promote_with_timeout(epoch, now_ms, promotion_timeout)
                {
                    Ok(report) => report,
                    Err(first_error) => {
                        trace.record(&format!(
                            "event=controller_promotion_reply_lost node={} epoch={epoch} code={}",
                            candidate.as_str(),
                            first_error.reason_code()
                        ))?;
                        let retry_timeout = runtime_timeout(
                            remaining_runtime(started, config.max_runtime),
                            config.authority_timeout,
                        )?;
                        client
                            .retry_last_command_with_timeout(retry_timeout)
                            .map_err(|retry_error| {
                                err(
                                    "LIFECYCLE_CONTROLLER_PROMOTION_AMBIGUOUS",
                                    format!(
                                        "node={} epoch={epoch} first={} retry={}",
                                        candidate.as_str(),
                                        first_error.reason_code(),
                                        retry_error.reason_code()
                                    ),
                                )
                            })?
                    }
                };
                let promotion_ms = promotion_started.elapsed().as_millis();
                controller.record_promotion_result(&promotion)?;
                if promotion.reason_code != LifecycleReasonCode::Promoted {
                    trace.record(&format!(
                        "event=controller_promotion_refused node={} epoch={epoch} code={}",
                        candidate.as_str(),
                        promotion.reason_code.as_str()
                    ))?;
                    return Err(err(
                        "LIFECYCLE_CONTROLLER_PROMOTION_REFUSED",
                        format!(
                            "node={} epoch={epoch} code={}",
                            candidate.as_str(),
                            promotion.reason_code.as_str()
                        ),
                    ));
                }
                failover_timing.record_promotion(candidate);

                promotions = promotions.checked_add(1).ok_or_else(|| {
                    err(
                        "LIFECYCLE_CONTROLLER_PROMOTION_EXHAUSTED",
                        "promotion counter overflow",
                    )
                })?;
                let (failure_detection_ms, lease_wait_ms, promotion_readiness_ms) = stages
                    .map(|value| {
                        (
                            value.failure_detection_ms,
                            value.lease_wait_ms,
                            value.promotion_readiness_ms,
                        )
                    })
                    .unwrap_or((0, 0, 0));
                trace.record(&format!(
                    "event=controller_promotion node={} epoch={epoch} now_ms={now_ms} code={} promotions={promotions} elapsed_ms={} failure_detection_ms={failure_detection_ms} lease_wait_ms={lease_wait_ms} promotion_readiness_ms={promotion_readiness_ms} promotion_ms={promotion_ms}",
                    candidate.as_str(),
                    promotion.reason_code.as_str(),
                    started.elapsed().as_millis()
                ))?;
                let mut final_report = promotion;
                let mut effect_ms = 0;
                if config.emit_test_effect {
                    let operation_id = controller_operation_id(epoch, candidate);
                    let effect_timeout = runtime_timeout(
                        remaining_runtime(started, config.max_runtime),
                        config.authority_timeout,
                    )?;
                    let effect_started = Instant::now();
                    final_report =
                        client.emit_with_timeout(epoch, now_ms, operation_id, effect_timeout)?;
                    effect_ms = effect_started.elapsed().as_millis();
                    if !final_report.reason_code.effect_succeeded() {
                        trace.record(&format!(
                            "event=controller_effect_refused node={} epoch={epoch} code={}",
                            candidate.as_str(),
                            final_report.reason_code.as_str()
                        ))?;
                        return Err(err(
                            "LIFECYCLE_CONTROLLER_EFFECT_REFUSED",
                            "promoted node did not pass the test EffectGate",
                        ));
                    }
                    trace.record(&format!(
                        "event=controller_effect node={} epoch={epoch} code={} effects={} elapsed_ms={} effect_ms={effect_ms}",
                        candidate.as_str(),
                        final_report.reason_code.as_str(),
                        final_report.effect_count,
                        started.elapsed().as_millis()
                    ))?;
                }
                if promotions == config.max_promotions {
                    let elapsed_ms = started.elapsed().as_millis();
                    trace.record(&format!(
                        "event=controller_complete node={} epoch={epoch} effects={} promotions={promotions} elapsed_ms={elapsed_ms}",
                        candidate.as_str(),
                        final_report.effect_count
                    ))?;
                    return Ok(LifecycleControllerReport {
                        promotions,
                        final_active: candidate,
                        final_epoch: epoch,
                        final_effect_count: final_report.effect_count,
                        elapsed_ms,
                        final_failure_detection_ms: failure_detection_ms,
                        final_lease_wait_ms: lease_wait_ms,
                        final_promotion_ms: promotion_ms,
                        final_effect_ms: effect_ms,
                    });
                }
            }
            LifecycleAutoDecision::Halt { reason } => {
                trace.record(&format!(
                    "event=controller_halt reason={}",
                    auto_reason_name(reason)
                ))?;
                return Err(err("LIFECYCLE_CONTROLLER_HALTED", auto_reason_name(reason)));
            }
            LifecycleAutoDecision::Stable { .. } | LifecycleAutoDecision::Hold { .. } => {}
        }
        let remaining = remaining_runtime(started, config.max_runtime);
        if remaining.is_zero() {
            trace.record("event=controller_halt reason=MAX_RUNTIME_EXCEEDED")?;
            return Err(err(
                "LIFECYCLE_CONTROLLER_TIMEOUT",
                "bounded automatic controller exceeded max runtime",
            ));
        }
        thread::sleep(config.poll_interval.min(remaining));
    }
}

fn remaining_runtime(started: Instant, max_runtime: Duration) -> Duration {
    max_runtime.saturating_sub(started.elapsed())
}

fn runtime_timeout(remaining: Duration, configured: Duration) -> Result<Duration, ClusterError> {
    if remaining < configured {
        return Err(err(
            "LIFECYCLE_CONTROLLER_TIMEOUT",
            "remaining runtime is shorter than the next I/O deadline",
        ));
    }
    Ok(configured)
}

fn controller_now_ms(
    logical_start_ms: u64,
    elapsed: Duration,
    logical_step_ms: u64,
) -> Result<u64, ClusterError> {
    let step = u128::from(logical_step_ms);
    let elapsed_bucket = (elapsed.as_millis() / step) * step;
    let elapsed_ms = u64::try_from(elapsed_bucket).map_err(|_error| {
        err(
            "LIFECYCLE_CONTROLLER_CLOCK_REFUSED",
            "monotonic elapsed time exceeds the logical clock range",
        )
    })?;
    logical_start_ms.checked_add(elapsed_ms).ok_or_else(|| {
        err(
            "LIFECYCLE_CONTROLLER_CLOCK_REFUSED",
            "logical controller clock overflow",
        )
    })
}

fn validate_config(config: &LifecycleControllerConfig) -> Result<(), ClusterError> {
    for (name, address) in [
        ("node-a", config.node_a_address),
        ("node-b", config.node_b_address),
    ] {
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(err(
                "LIFECYCLE_CONTROLLER_ADDRESS_REFUSED",
                format!("{name} address must be a bound loopback endpoint"),
            ));
        }
    }
    if config.node_a_address == config.node_b_address {
        return Err(err(
            "LIFECYCLE_CONTROLLER_ADDRESS_REFUSED",
            "Node A and Node B endpoints must differ",
        ));
    }
    if !(2..=16).contains(&config.failure_threshold) {
        return Err(err(
            "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
            "failure threshold must be between 2 and 16",
        ));
    }
    if config.max_promotions == 0 || config.max_promotions > MAX_PROMOTIONS {
        return Err(err(
            "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
            "max promotions must be between 1 and 16",
        ));
    }
    if config.logical_step_ms == 0 || config.logical_step_ms > MAX_LOGICAL_STEP_MS {
        return Err(err(
            "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
            "logical step must be between 1 and 50 ms",
        ));
    }
    validate_duration(
        config.poll_interval,
        MAX_POLL_MS,
        "poll interval",
        "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
    )?;
    validate_duration(
        config.observation_timeout,
        MAX_TIMEOUT_MS,
        "observation timeout",
        "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
    )?;
    validate_duration(
        config.authority_timeout,
        MAX_TIMEOUT_MS,
        "authority timeout",
        "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
    )?;
    validate_duration(
        config.max_runtime,
        MAX_RUNTIME_MS,
        "max runtime",
        "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
    )?;
    if config.max_runtime <= config.authority_timeout.max(config.observation_timeout) {
        return Err(err(
            "LIFECYCLE_CONTROLLER_POLICY_REFUSED",
            "max runtime must exceed both I/O timeouts",
        ));
    }
    Ok(())
}

fn validate_duration(
    value: Duration,
    maximum_ms: u128,
    name: &str,
    code: &'static str,
) -> Result<(), ClusterError> {
    if value.is_zero() || value.as_millis() == 0 || value.as_millis() > maximum_ms {
        return Err(err(
            code,
            format!("{name} must be non-zero and at most {maximum_ms} ms"),
        ));
    }
    Ok(())
}

fn observe(
    client: &mut LifecycleClient,
    now_ms: u64,
    timeout: Duration,
    trace: &mut ControllerTrace,
    node: LifecycleNodeId,
    previous: &mut Option<ObservationState>,
) -> Result<Option<crate::lifecycle::LifecycleReport>, ClusterError> {
    let (state, report) = match client.status_with_timeout(now_ms, timeout) {
        Ok(report) => (ObservationState::Available, Some(report)),
        Err(error) => {
            let code = error.reason_code();
            if !is_availability_error(code) {
                trace.record(&format!(
                    "event=controller_observation node={} now_ms={now_ms} status=REFUSED code={code}",
                    node.as_str()
                ))?;
                return Err(err(
                    "LIFECYCLE_CONTROLLER_OBSERVATION_REFUSED",
                    format!("node={} untrusted observation code={code}", node.as_str()),
                ));
            }
            (ObservationState::Missing(code), None)
        }
    };
    if *previous != Some(state) {
        match state {
            ObservationState::Available => trace.record(&format!(
                "event=controller_observation node={} now_ms={now_ms} status=AVAILABLE",
                node.as_str()
            ))?,
            ObservationState::Missing(code) => trace.record(&format!(
                "event=controller_observation node={} now_ms={now_ms} status=MISSING code={code}",
                node.as_str()
            ))?,
        }
        *previous = Some(state);
    }
    Ok(report)
}

fn is_availability_error(code: &str) -> bool {
    matches!(
        code,
        "LIFECYCLE_NODE_UNAVAILABLE"
            | "LIFECYCLE_COMMAND_WRITE_FAILED"
            | "LIFECYCLE_RESPONSE_READ_FAILED"
            | "LIFECYCLE_RESPONSE_MISSING"
    )
}

fn controller_operation_id(epoch: u64, node: LifecycleNodeId) -> [u8; 16] {
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&epoch.to_be_bytes());
    id[8] = match node {
        LifecycleNodeId::NodeA => 0xa1,
        LifecycleNodeId::NodeB => 0xb2,
    };
    id[15] = 1;
    id
}

fn decision_label(decision: LifecycleAutoDecision) -> String {
    match decision {
        LifecycleAutoDecision::Stable { active, epoch } => {
            format!("STABLE:{}:{epoch}", active.as_str())
        }
        LifecycleAutoDecision::Hold { reason } => auto_reason_name(reason).to_owned(),
        LifecycleAutoDecision::Promote { candidate, epoch } => {
            format!("PROMOTE:{}:{epoch}", candidate.as_str())
        }
        LifecycleAutoDecision::Halt { reason } => {
            format!("HALT:{}", auto_reason_name(reason))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservationState {
    Available,
    Missing(&'static str),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailoverStages {
    failure_detection_ms: u128,
    lease_wait_ms: u128,
    promotion_readiness_ms: u128,
}

#[derive(Default)]
struct FailoverTiming {
    active: Option<LifecycleNodeId>,
    failure_started_ms: Option<u128>,
    failure_detected_ms: Option<u128>,
    lease_ready_ms: Option<u128>,
}

impl FailoverTiming {
    fn record_observation(
        &mut self,
        node: LifecycleNodeId,
        report: Option<&crate::lifecycle::LifecycleReport>,
        observation_started_ms: u128,
    ) {
        if self.active != Some(node) {
            return;
        }
        match report.map(|value| value.state) {
            Some(crate::lifecycle::LifecycleState::Active) => self.reset_failure(),
            None
            | Some(
                crate::lifecycle::LifecycleState::SelfFenced
                | crate::lifecycle::LifecycleState::Draining,
            ) => {
                if self.failure_started_ms.is_none() {
                    self.failure_started_ms = Some(observation_started_ms);
                }
            }
            Some(_) => {}
        }
    }

    fn record_promotion(&mut self, active: LifecycleNodeId) {
        self.active = Some(active);
        self.reset_failure();
    }

    fn record_decision(&mut self, decision: LifecycleAutoDecision, elapsed_ms: u128) {
        match decision {
            LifecycleAutoDecision::Stable { active, .. } => {
                self.active = Some(active);
                self.reset_failure();
            }
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            } => self.record_detection(elapsed_ms),
            LifecycleAutoDecision::Hold {
                reason:
                    LifecycleAutoReason::WitnessUnavailable
                    | LifecycleAutoReason::CandidateUnavailable
                    | LifecycleAutoReason::CandidateLagging,
            }
            | LifecycleAutoDecision::Promote { .. } => {
                self.record_detection(elapsed_ms);
                if self.lease_ready_ms.is_none() {
                    self.lease_ready_ms = Some(elapsed_ms);
                }
            }
            LifecycleAutoDecision::Hold { .. } | LifecycleAutoDecision::Halt { .. } => {}
        }
    }

    fn stages(&self, promotion_started_ms: u128) -> Option<FailoverStages> {
        let failure_started_ms = self.failure_started_ms?;
        let failure_detected_ms = self.failure_detected_ms?;
        let lease_ready_ms = self.lease_ready_ms?;
        Some(FailoverStages {
            failure_detection_ms: failure_detected_ms.saturating_sub(failure_started_ms),
            lease_wait_ms: lease_ready_ms.saturating_sub(failure_detected_ms),
            promotion_readiness_ms: promotion_started_ms.saturating_sub(lease_ready_ms),
        })
    }

    fn record_detection(&mut self, elapsed_ms: u128) {
        if self.failure_started_ms.is_some() && self.failure_detected_ms.is_none() {
            self.failure_detected_ms = Some(elapsed_ms);
        }
    }

    fn reset_failure(&mut self) {
        self.failure_started_ms = None;
        self.failure_detected_ms = None;
        self.lease_ready_ms = None;
    }
}

fn auto_reason_name(reason: LifecycleAutoReason) -> &'static str {
    match reason {
        LifecycleAutoReason::WaitingForFailureThreshold => "WAITING_FOR_FAILURE_THRESHOLD",
        LifecycleAutoReason::WaitingForLeaseGuard => "WAITING_FOR_LEASE_GUARD",
        LifecycleAutoReason::WitnessUnavailable => "WITNESS_UNAVAILABLE",
        LifecycleAutoReason::CandidateUnavailable => "CANDIDATE_UNAVAILABLE",
        LifecycleAutoReason::CandidateLagging => "CANDIDATE_LAGGING",
        LifecycleAutoReason::PromotionPending => "PROMOTION_PENDING",
        LifecycleAutoReason::PromotionWindowMissed => "PROMOTION_WINDOW_MISSED",
        LifecycleAutoReason::AmbiguousActive => "AMBIGUOUS_ACTIVE",
    }
}

struct ControllerTrace {
    file: File,
}

impl ControllerTrace {
    fn create(path: &Path) -> Result<Self, ClusterError> {
        reject_symlink_components(path)?;
        prepare_file_parent(path)?;
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| {
                err(
                    "LIFECYCLE_CONTROLLER_TRACE_REFUSED",
                    format!("{}: {error}", path.display()),
                )
            })?;
        Ok(Self { file })
    }

    fn record(&mut self, event: &str) -> Result<(), ClusterError> {
        self.file
            .write_all(event.as_bytes())
            .and_then(|()| self.file.write_all(b"\n"))
            .and_then(|()| self.file.sync_data())
            .map_err(|error| err("LIFECYCLE_CONTROLLER_TRACE_FAILED", error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> LifecycleControllerConfig {
        LifecycleControllerConfig {
            node_a_address: SocketAddr::from(([127, 0, 0, 1], 10_001)),
            node_b_address: SocketAddr::from(([127, 0, 0, 1], 10_002)),
            node_a_public_key_file: PathBuf::from("node-a.pub"),
            node_b_public_key_file: PathBuf::from("node-b.pub"),
            controller_signing_key_file: PathBuf::from("controller.key"),
            trace_file: PathBuf::from("controller.trace"),
            failure_threshold: 2,
            max_promotions: 2,
            logical_step_ms: 5,
            poll_interval: Duration::from_millis(10),
            observation_timeout: Duration::from_millis(25),
            authority_timeout: Duration::from_millis(100),
            max_runtime: Duration::from_secs(2),
            emit_test_effect: false,
        }
    }

    #[test]
    fn policy_bounds_fail_before_key_or_trace_access() {
        let mut invalid = config();
        invalid.failure_threshold = 1;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        invalid = config();
        invalid.max_promotions = 17;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        invalid = config();
        invalid.logical_step_ms = 51;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        invalid = config();
        invalid.max_runtime = invalid.authority_timeout;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        invalid = config();
        invalid.observation_timeout = Duration::ZERO;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        invalid = config();
        invalid.authority_timeout = Duration::from_millis(5_001);
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_POLICY_REFUSED")
        );
        let mut independent = config();
        independent.observation_timeout = Duration::from_millis(100);
        independent.authority_timeout = Duration::from_millis(25);
        independent.max_runtime = Duration::from_millis(200);
        assert_eq!(validate_config(&independent), Ok(()));
    }

    #[test]
    fn runtime_timeout_refuses_io_that_cannot_finish_before_deadline() {
        assert_eq!(
            runtime_timeout(Duration::from_millis(2), Duration::from_secs(5))
                .map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_TIMEOUT")
        );
        assert_eq!(
            runtime_timeout(Duration::from_secs(5), Duration::from_secs(3)),
            Ok(Duration::from_secs(3))
        );
    }

    #[test]
    fn failover_timing_separates_detection_from_lease_wait() {
        let mut timing = FailoverTiming::default();
        timing.record_promotion(LifecycleNodeId::NodeA);
        timing.record_observation(LifecycleNodeId::NodeA, None, 100);
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForFailureThreshold,
            },
            120,
        );
        timing.record_observation(LifecycleNodeId::NodeA, None, 120);
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            },
            145,
        );
        timing.record_decision(
            LifecycleAutoDecision::Promote {
                candidate: LifecycleNodeId::NodeB,
                epoch: 2,
            },
            225,
        );

        assert_eq!(
            timing.stages(225),
            Some(FailoverStages {
                failure_detection_ms: 45,
                lease_wait_ms: 80,
                promotion_readiness_ms: 0,
            })
        );
    }

    #[test]
    fn failover_timing_counts_authenticated_self_fence_as_detection() {
        let mut timing = FailoverTiming::default();
        timing.record_promotion(LifecycleNodeId::NodeA);
        let report = crate::lifecycle::LifecycleReport {
            node_id: LifecycleNodeId::NodeA,
            reason_code: LifecycleReasonCode::Status,
            state: crate::lifecycle::LifecycleState::SelfFenced,
            highest_epoch: 1,
            incarnation: 1,
            store_generation: 1,
            effect_count: 0,
            commit_index: 1,
            state_root: [1; 32],
            lease_expires_at_ms: 0,
        };
        timing.record_observation(LifecycleNodeId::NodeA, Some(&report), 300);
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            },
            325,
        );
        timing.record_decision(
            LifecycleAutoDecision::Promote {
                candidate: LifecycleNodeId::NodeB,
                epoch: 2,
            },
            400,
        );

        assert_eq!(
            timing.stages(400),
            Some(FailoverStages {
                failure_detection_ms: 25,
                lease_wait_ms: 75,
                promotion_readiness_ms: 0,
            })
        );
    }

    #[test]
    fn failover_timing_keeps_post_lease_candidate_delay_out_of_lease_wait() {
        let mut timing = FailoverTiming::default();
        timing.record_promotion(LifecycleNodeId::NodeA);
        timing.record_observation(LifecycleNodeId::NodeA, None, 100);
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            },
            145,
        );
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateUnavailable,
            },
            225,
        );
        timing.record_decision(
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateUnavailable,
            },
            725,
        );
        timing.record_decision(
            LifecycleAutoDecision::Promote {
                candidate: LifecycleNodeId::NodeB,
                epoch: 2,
            },
            730,
        );

        assert_eq!(
            timing.stages(730),
            Some(FailoverStages {
                failure_detection_ms: 45,
                lease_wait_ms: 80,
                promotion_readiness_ms: 505,
            })
        );
    }

    #[test]
    fn endpoints_and_effect_operation_ids_are_unambiguous() {
        let mut invalid = config();
        invalid.node_b_address = invalid.node_a_address;
        assert_eq!(
            validate_config(&invalid).map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_ADDRESS_REFUSED")
        );
        assert_ne!(
            controller_operation_id(1, LifecycleNodeId::NodeA),
            controller_operation_id(1, LifecycleNodeId::NodeB)
        );
        assert_ne!(
            controller_operation_id(1, LifecycleNodeId::NodeA),
            controller_operation_id(2, LifecycleNodeId::NodeA)
        );
    }

    #[test]
    fn only_transport_absence_is_eligible_for_failure_suspicion() {
        for code in [
            "LIFECYCLE_NODE_UNAVAILABLE",
            "LIFECYCLE_COMMAND_WRITE_FAILED",
            "LIFECYCLE_RESPONSE_READ_FAILED",
            "LIFECYCLE_RESPONSE_MISSING",
        ] {
            assert!(is_availability_error(code), "{code}");
        }
        for code in [
            "LIFECYCLE_RESPONSE_AUTH_REFUSED",
            "LIFECYCLE_RESPONSE_BINDING_REFUSED",
            "LIFECYCLE_RESPONSE_MALFORMED",
            "SOCKET_CONFIG_FAILED",
        ] {
            assert!(!is_availability_error(code), "{code}");
        }
    }

    #[test]
    fn logical_clock_is_monotonic_quantized_and_never_leads_elapsed_time() {
        let start = 1_000;
        for (elapsed_ms, expected) in [(0, 1_000), (9, 1_000), (27, 1_020)] {
            assert_eq!(
                controller_now_ms(start, Duration::from_millis(elapsed_ms), 10)
                    .map_err(|error| error.reason_code()),
                Ok(expected)
            );
        }
        for elapsed_ms in 0_u64..100 {
            let expected = start + (elapsed_ms / 10) * 10;
            assert_eq!(
                controller_now_ms(start, Duration::from_millis(elapsed_ms), 10)
                    .map_err(|error| error.reason_code()),
                Ok(expected)
            );
            assert!(expected <= start + elapsed_ms);
        }
        assert_eq!(
            controller_now_ms(u64::MAX, Duration::from_millis(10), 10)
                .map_err(|error| error.reason_code()),
            Err("LIFECYCLE_CONTROLLER_CLOCK_REFUSED")
        );
    }
}
