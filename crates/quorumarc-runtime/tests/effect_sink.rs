use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_core::{
    AuthorityState, CommitIndex, EffectGate, Epoch, FenceMechanism, FenceReceipt,
    GateError, GateRecoveryState, GateState, HealthAttestation, Incarnation, LeaseGrant, NodeId,
    PolicyHash, PromotionProof, QuorumCertificate, SafetyPolicy, SelfFenceReason, StateEvidence,
    StateRoot, TrustedClock, ValidatedPromotion, WorkloadId, validate_promotion,
};
use quorumarc_runtime::{
    EffectEmitError, EffectOutcome, EffectReasonCode, MAX_TEST_EFFECT_SIZE, TestEffectActor,
};

const NOW: u64 = 20_000;

#[derive(Clone)]
struct ManualClock(Arc<AtomicU64>);

impl ManualClock {
    fn new(now_ms: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now_ms)))
    }

    fn set(&self, now_ms: u64) {
        self.0.store(now_ms, Ordering::SeqCst);
    }
}

impl TrustedClock for ManualClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn value_or_abort<T, E>(result: Result<T, E>) -> T {
    let Ok(value) = result else {
        std::process::abort();
    };
    value
}

fn node(value: &str) -> NodeId {
    value_or_abort(NodeId::new(value))
}

fn workload() -> WorkloadId {
    value_or_abort(WorkloadId::new("payments"))
}

fn policy_hash() -> PolicyHash {
    PolicyHash::new([3; 32])
}

fn authorization() -> ValidatedPromotion {
    let candidate = node("node-a");
    let epoch = Epoch(1);
    let proof = PromotionProof {
        workload: workload(),
        candidate: candidate.clone(),
        candidate_incarnation: Incarnation(1),
        epoch,
        policy_hash: policy_hash(),
        quorum: QuorumCertificate {
            epoch,
            workload: workload(),
            candidate: candidate.clone(),
            candidate_incarnation: Incarnation(1),
            policy_hash: policy_hash(),
            required_commit: CommitIndex(4),
            state_root: StateRoot::new([8; 32]),
            lease_not_before_ms: NOW,
            lease_expires_at_ms: NOW + 100,
            voters: vec![candidate.clone(), node("witness")],
        },
        fence: FenceReceipt {
            epoch,
            target: None,
            verifier: node("witness"),
            mechanism: FenceMechanism::Bootstrap,
            observed_at_ms: NOW - 5,
        },
        state: StateEvidence {
            required_commit: CommitIndex(4),
            durable_commit: CommitIndex(5),
            state_root: StateRoot::new([8; 32]),
            observed_at_ms: NOW - 5,
        },
        health: HealthAttestation {
            workload: workload(),
            node: candidate.clone(),
            incarnation: Incarnation(1),
            epoch,
            healthy: true,
            passed_checks: 2,
            observed_at_ms: NOW - 5,
        },
        lease: LeaseGrant {
            workload: workload(),
            holder: candidate,
            incarnation: Incarnation(1),
            epoch,
            not_before_ms: NOW,
            expires_at_ms: NOW + 100,
        },
    };
    let policy = value_or_abort(SafetyPolicy::new(
        workload(),
        policy_hash(),
        [node("node-a"), node("node-b")],
        BTreeSet::from([node("node-a"), node("node-b"), node("witness")]),
        2,
        Some(node("witness")),
        2,
        100,
        500,
        10,
        true,
    ));
    value_or_abort(validate_promotion(
        &proof,
        &AuthorityState::initial(),
        &policy,
        NOW,
    ))
}

fn actor() -> (TestEffectActor<ManualClock>, ManualClock) {
    let clock = ManualClock::new(NOW);
    let gate = EffectGate::recover(
        node("node-a"),
        workload(),
        policy_hash(),
        GateRecoveryState::new(Epoch(0), Incarnation(1), NOW - 10),
        clock.clone(),
    );
    (TestEffectActor::new(gate), clock)
}

fn activate(actor: &mut TestEffectActor<ManualClock>) {
    let record = value_or_abort(actor.stage(authorization()));
    value_or_abort(actor.confirm_persisted(&record));
    let _receipt = value_or_abort(actor.activate());
}

#[test]
fn sink_cannot_emit_before_core_gate_activation() {
    let (mut actor, _) = actor();
    let result = actor.emit([1; 16], node("node-a"), Epoch(1), b"write");
    assert_eq!(
        result,
        Err(EffectEmitError::Gate(quorumarc_core::GateError::GateClosed))
    );
    assert_eq!(actor.records().len(), 0);
}

#[test]
fn live_gate_records_once_and_rechecks_exact_retry() {
    let (mut actor, _) = actor();
    activate(&mut actor);
    assert_eq!(
        actor.emit([1; 16], node("node-a"), Epoch(1), b"write"),
        Ok(EffectOutcome::Recorded)
    );
    assert_eq!(
        actor.emit([1; 16], node("node-a"), Epoch(1), b"write"),
        Ok(EffectOutcome::AlreadyRecorded)
    );
    assert_eq!(actor.records().len(), 1);
}

#[test]
fn operation_id_reuse_with_changed_effect_self_fences() {
    let (mut actor, _) = actor();
    activate(&mut actor);
    assert!(
        actor
            .emit([2; 16], node("node-a"), Epoch(1), b"first")
            .is_ok()
    );
    let result = actor.emit([2; 16], node("node-a"), Epoch(1), b"changed");
    assert_eq!(result, Err(EffectEmitError::OperationIdConflict));
    assert_eq!(
        result.err().map(EffectEmitError::reason_code),
        Some(EffectReasonCode::OperationIdConflict)
    );
    assert!(matches!(
        actor.gate_state(),
        GateState::SelfFenced {
            reason: SelfFenceReason::SafetyFault,
            ..
        }
    ));
}

#[test]
fn exact_retry_after_lease_expiry_is_refused_and_self_fenced() {
    let (mut actor, clock) = actor();
    activate(&mut actor);
    assert!(
        actor
            .emit([3; 16], node("node-a"), Epoch(1), b"once")
            .is_ok()
    );
    clock.set(NOW + 100);
    let result = actor.emit([3; 16], node("node-a"), Epoch(1), b"once");
    assert_eq!(
        result,
        Err(EffectEmitError::Gate(
            quorumarc_core::GateError::LeaseExpired
        ))
    );
    assert_eq!(actor.records().len(), 1);
}

#[test]
fn operation_and_payload_limits_are_checked_before_any_effect() {
    let (mut closed, _) = actor();
    assert_eq!(
        closed.emit([0; 16], node("node-a"), Epoch(1), b"ignored"),
        Err(EffectEmitError::ZeroOperationId)
    );
    let oversized = vec![7; MAX_TEST_EFFECT_SIZE + 1];
    assert_eq!(
        closed.emit([7; 16], node("node-a"), Epoch(1), &oversized),
        Err(EffectEmitError::PayloadTooLarge {
            actual: MAX_TEST_EFFECT_SIZE + 1,
            maximum: MAX_TEST_EFFECT_SIZE,
        })
    );
    assert_eq!(closed.records().len(), 0);

    let (mut live, _) = actor();
    activate(&mut live);
    let maximum = vec![9; MAX_TEST_EFFECT_SIZE];
    assert_eq!(
        live.emit([8; 16], node("node-a"), Epoch(1), &maximum),
        Ok(EffectOutcome::Recorded)
    );
    let Some(record) = live.records().next() else {
        std::process::abort();
    };
    assert_eq!(record.operation_id(), &[8; 16]);
    assert_eq!(record.holder(), &node("node-a"));
    assert_eq!(record.epoch(), Epoch(1));
    assert_eq!(record.payload(), maximum.as_slice());
}

#[test]
fn new_effect_requires_exact_live_holder_and_epoch() {
    let (mut actor, _) = actor();
    activate(&mut actor);

    assert_eq!(
        actor.emit([9; 16], node("node-b"), Epoch(1), b"wrong holder"),
        Err(EffectEmitError::Gate(GateError::WrongCandidate))
    );
    assert_eq!(
        actor.emit([10; 16], node("node-a"), Epoch(0), b"stale epoch"),
        Err(EffectEmitError::Gate(GateError::StaleAuthorization))
    );
    assert_eq!(actor.records().len(), 0);
    assert_eq!(
        actor.emit([11; 16], node("node-a"), Epoch(1), b"bound"),
        Ok(EffectOutcome::Recorded)
    );
}

#[test]
fn rollback_before_a_new_effect_self_fences_without_recording() {
    let (mut actor, clock) = actor();
    activate(&mut actor);
    clock.set(NOW - 1);

    assert_eq!(
        actor.emit([12; 16], node("node-a"), Epoch(1), b"must not escape"),
        Err(EffectEmitError::Gate(GateError::ClockRollback))
    );
    assert_eq!(actor.records().len(), 0);
    assert_eq!(
        actor.gate_state(),
        &GateState::SelfFenced {
            last_epoch: Epoch(1),
            reason: SelfFenceReason::SafetyFault,
        }
    );
}

#[test]
fn actor_preserves_durable_transition_order_and_exact_record() {
    let (mut later_actor, later_clock) = actor();
    later_clock.set(NOW + 1);
    let later_record = value_or_abort(later_actor.stage(authorization()));

    let (mut actor, _) = actor();
    assert_eq!(actor.activate(), Err(GateError::NotPrepared));
    assert_eq!(
        actor.confirm_persisted(&later_record),
        Err(GateError::NotStaged)
    );
    let exact_record = value_or_abort(actor.stage(authorization()));
    assert_eq!(
        actor.confirm_persisted(&later_record),
        Err(GateError::PersistenceMismatch)
    );
    assert!(matches!(actor.gate_state(), GateState::Staged { .. }));
    assert!(actor.confirm_persisted(&exact_record).is_ok());
    assert!(actor.activate().is_ok());
    assert_eq!(actor.tick(), Ok(false));
    actor.close();
    assert_eq!(
        actor.emit([13; 16], node("node-a"), Epoch(1), b"closed"),
        Err(EffectEmitError::Gate(GateError::GateClosed))
    );
    assert_eq!(actor.records().len(), 0);
}

#[test]
fn every_operation_identity_binding_conflict_self_fences() {
    let conflicts = [
        (node("node-b"), Epoch(1), &b"same"[..]),
        (node("node-a"), Epoch(2), &b"same"[..]),
        (node("node-a"), Epoch(1), &b"different"[..]),
    ];

    for (holder, epoch, payload) in conflicts {
        let (mut actor, _) = actor();
        activate(&mut actor);
        assert_eq!(
            actor.emit([14; 16], node("node-a"), Epoch(1), b"same"),
            Ok(EffectOutcome::Recorded)
        );
        assert_eq!(
            actor.emit([14; 16], holder, epoch, payload),
            Err(EffectEmitError::OperationIdConflict)
        );
        assert!(matches!(
            actor.gate_state(),
            GateState::SelfFenced {
                reason: SelfFenceReason::SafetyFault,
                ..
            }
        ));
        assert_eq!(actor.records().len(), 1);
    }
}

#[test]
fn refusal_reason_codes_are_stable_for_all_gate_failures() {
    let gate_cases = [
        (
            GateError::GateBindingMismatch,
            EffectReasonCode::GateBindingMismatch,
            "EFFECT_REFUSED_GATE_BINDING_MISMATCH",
        ),
        (
            GateError::WrongCandidate,
            EffectReasonCode::WrongHolder,
            "EFFECT_REFUSED_WRONG_HOLDER",
        ),
        (
            GateError::IncarnationMismatch,
            EffectReasonCode::IncarnationMismatch,
            "EFFECT_REFUSED_INCARNATION_MISMATCH",
        ),
        (
            GateError::StaleAuthorization,
            EffectReasonCode::StaleEpoch,
            "EFFECT_REFUSED_STALE_EPOCH",
        ),
        (
            GateError::AlreadyOpen,
            EffectReasonCode::AlreadyOpen,
            "EFFECT_REFUSED_ALREADY_OPEN",
        ),
        (
            GateError::NotStaged,
            EffectReasonCode::NotStaged,
            "EFFECT_REFUSED_NOT_STAGED",
        ),
        (
            GateError::PersistenceMismatch,
            EffectReasonCode::PersistenceMismatch,
            "EFFECT_REFUSED_PERSISTENCE_MISMATCH",
        ),
        (
            GateError::NotPrepared,
            EffectReasonCode::NotPrepared,
            "EFFECT_REFUSED_NOT_PREPARED",
        ),
        (
            GateError::LeaseNotStarted,
            EffectReasonCode::LeaseNotStarted,
            "EFFECT_REFUSED_LEASE_NOT_STARTED",
        ),
        (
            GateError::LeaseExpired,
            EffectReasonCode::LeaseExpired,
            "EFFECT_REFUSED_LEASE_EXPIRED",
        ),
        (
            GateError::GateClosed,
            EffectReasonCode::GateClosed,
            "EFFECT_REFUSED_GATE_CLOSED",
        ),
        (
            GateError::ClockRollback,
            EffectReasonCode::ClockRollback,
            "EFFECT_REFUSED_CLOCK_ROLLBACK",
        ),
    ];

    for (gate_error, expected, spelling) in gate_cases {
        let reason = EffectEmitError::Gate(gate_error).reason_code();
        assert_eq!(reason, expected);
        assert_eq!(reason.as_str(), spelling);
    }

    let direct_cases = [
        (
            EffectEmitError::ZeroOperationId,
            EffectReasonCode::ZeroOperationId,
            "EFFECT_REFUSED_ZERO_OPERATION_ID",
        ),
        (
            EffectEmitError::PayloadTooLarge {
                actual: MAX_TEST_EFFECT_SIZE + 1,
                maximum: MAX_TEST_EFFECT_SIZE,
            },
            EffectReasonCode::PayloadTooLarge,
            "EFFECT_REFUSED_PAYLOAD_TOO_LARGE",
        ),
        (
            EffectEmitError::OperationIdConflict,
            EffectReasonCode::OperationIdConflict,
            "EFFECT_REFUSED_OPERATION_ID_CONFLICT",
        ),
    ];
    for (error, expected, spelling) in direct_cases {
        let reason = error.reason_code();
        assert_eq!(reason, expected);
        assert_eq!(reason.as_str(), spelling);
    }
}

#[test]
fn actor_tick_self_fences_exactly_at_lease_expiry() {
    let (mut actor, clock) = actor();
    activate(&mut actor);
    clock.set(NOW + 99);
    assert_eq!(actor.tick(), Ok(false));
    clock.set(NOW + 100);
    assert_eq!(actor.tick(), Ok(true));
    assert_eq!(
        actor.gate_state(),
        &GateState::SelfFenced {
            last_epoch: Epoch(1),
            reason: SelfFenceReason::LeaseExpired,
        }
    );
}
