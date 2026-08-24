use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_core::{
    AuthorityState, CommitIndex, EffectGate, Epoch, FenceMechanism, FenceReceipt,
    GateRecoveryState, GateState, HealthAttestation, Incarnation, LeaseGrant, NodeId, PolicyHash,
    PromotionProof, QuorumCertificate, SafetyPolicy, SelfFenceReason, StateEvidence, StateRoot,
    TrustedClock, ValidatedPromotion, WorkloadId, validate_promotion,
};
use quorumarc_runtime::{
    EffectEmitError, EffectOutcome, EffectReasonCode, TestEffectActor,
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
    assert_eq!(result, Err(EffectEmitError::Gate(quorumarc_core::GateError::GateClosed)));
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
    assert!(actor.emit([2; 16], node("node-a"), Epoch(1), b"first").is_ok());
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
    assert!(actor.emit([3; 16], node("node-a"), Epoch(1), b"once").is_ok());
    clock.set(NOW + 100);
    let result = actor.emit([3; 16], node("node-a"), Epoch(1), b"once");
    assert_eq!(
        result,
        Err(EffectEmitError::Gate(quorumarc_core::GateError::LeaseExpired))
    );
    assert_eq!(actor.records().len(), 1);
}
