//! Deterministic exploration of a compact two-node-plus-witness safety model.
//!
//! The model intentionally focuses on authority rather than workload recovery.
//! Promotion requires candidate+witness quorum and proof that the old gate is
//! ineffective through fencing or lease expiry. Partitions alone never fence.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::{self, Display, Formatter};

use quorumarc_core::{
    AuthorityState, CommitIndex, EffectGate, Epoch, FenceMechanism, FenceReceipt,
    GateRecoveryState, HealthAttestation, Incarnation, LeaseGrant, NodeId, PolicyHash,
    PromotionProof, ProofError, QuorumCertificate, SafetyPolicy, StateEvidence, StateRoot,
    TrustedClock, WorkloadId, validate_promotion,
};

/// Model node identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Node {
    /// First data node.
    A,
    /// Second data node.
    B,
}

impl Display for Node {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::A => "A",
            Self::B => "B",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GateLease {
    epoch: u64,
    incarnation: u64,
    expires_at_tick: u8,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NodeState {
    powered: bool,
    connected_to_witness: bool,
    fenced: bool,
    caught_up: bool,
    accepted_epoch: u64,
    incarnation: u64,
    gate: Option<GateLease>,
}

impl NodeState {
    const fn initial() -> Self {
        Self {
            powered: true,
            connected_to_witness: true,
            fenced: false,
            caught_up: true,
            accepted_epoch: 0,
            incarnation: 1,
            gate: None,
        }
    }

    const fn gate_is_effective(self, now_tick: u8) -> bool {
        self.powered
            && !self.fenced
            && matches!(
                self.gate,
                Some(lease)
                    if lease.epoch > 0
                        && lease.incarnation == self.incarnation
                        && now_tick < lease.expires_at_tick
            )
    }
}

/// Complete compact model state.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ModelState {
    now_tick: u8,
    epoch: u64,
    metadata_holder: Option<Node>,
    metadata_lease_expires_at_tick: Option<u8>,
    witness_up: bool,
    a: NodeState,
    b: NodeState,
}

impl Default for ModelState {
    fn default() -> Self {
        Self {
            now_tick: 0,
            epoch: 0,
            metadata_holder: None,
            metadata_lease_expires_at_tick: None,
            witness_up: true,
            a: NodeState::initial(),
            b: NodeState::initial(),
        }
    }
}

impl ModelState {
    fn node(&self, node: Node) -> NodeState {
        match node {
            Node::A => self.a,
            Node::B => self.b,
        }
    }

    fn node_mut(&mut self, node: Node) -> &mut NodeState {
        match node {
            Node::A => &mut self.a,
            Node::B => &mut self.b,
        }
    }

    /// Current logical time tick.
    #[must_use]
    pub const fn now_tick(&self) -> u8 {
        self.now_tick
    }

    /// Number of nodes that can currently create external effects.
    #[must_use]
    pub fn active_writers(&self) -> usize {
        usize::from(self.a.gate_is_effective(self.now_tick))
            + usize::from(self.b.gate_is_effective(self.now_tick))
    }

    /// Highest promotion epoch committed by the model.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Holder recorded in the compact metadata model.
    #[must_use]
    pub const fn metadata_holder(&self) -> Option<Node> {
        self.metadata_holder
    }
}

/// Fault or control action explored at every state.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Action {
    /// Disconnect A from the witness/control path.
    PartitionA,
    /// Restore A's witness/control path.
    HealA,
    /// Disconnect B from the witness/control path.
    PartitionB,
    /// Restore B's witness/control path.
    HealB,
    /// Stop the witness.
    StopWitness,
    /// Restore the witness.
    StartWitness,
    /// Crash A; a crash stops local effects but is not a fence receipt.
    CrashA,
    /// Restart A with its stale gate closed.
    RestartA,
    /// Crash B; a crash stops local effects but is not a fence receipt.
    CrashB,
    /// Restart B with its stale gate closed.
    RestartB,
    /// Apply authoritative fencing to A.
    FenceA,
    /// Apply authoritative fencing to B.
    FenceB,
    /// Mark A's durable state behind the required commit.
    LagA,
    /// Catch A up to the required commit.
    CatchUpA,
    /// Mark B's durable state behind the required commit.
    LagB,
    /// Catch B up to the required commit.
    CatchUpB,
    /// Request a proof-carrying promotion for A.
    PromoteA,
    /// Request a proof-carrying promotion for B.
    PromoteB,
    /// Advance logical time by one lease tick.
    AdvanceTime,
}

impl Action {
    const ALL: [Self; 19] = [
        Self::PartitionA,
        Self::HealA,
        Self::PartitionB,
        Self::HealB,
        Self::StopWitness,
        Self::StartWitness,
        Self::CrashA,
        Self::RestartA,
        Self::CrashB,
        Self::RestartB,
        Self::FenceA,
        Self::FenceB,
        Self::LagA,
        Self::CatchUpA,
        Self::LagB,
        Self::CatchUpB,
        Self::PromoteA,
        Self::PromoteB,
        Self::AdvanceTime,
    ];

    fn candidate(self) -> Option<Node> {
        match self {
            Self::PromoteA => Some(Node::A),
            Self::PromoteB => Some(Node::B),
            _ => None,
        }
    }
}

impl Display for Action {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PartitionA => "partition-a",
            Self::HealA => "heal-a",
            Self::PartitionB => "partition-b",
            Self::HealB => "heal-b",
            Self::StopWitness => "stop-witness",
            Self::StartWitness => "start-witness",
            Self::CrashA => "crash-a",
            Self::RestartA => "restart-a",
            Self::CrashB => "crash-b",
            Self::RestartB => "restart-b",
            Self::FenceA => "fence-a",
            Self::FenceB => "fence-b",
            Self::LagA => "lag-a",
            Self::CatchUpA => "catch-up-a",
            Self::LagB => "lag-b",
            Self::CatchUpB => "catch-up-b",
            Self::PromoteA => "promote-a",
            Self::PromoteB => "promote-b",
            Self::AdvanceTime => "advance-time",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rejection {
    NoQuorum,
    CandidateUnavailable,
    CandidateBehind,
    OldGateEffective,
    AlreadyEffective,
    CoreRefused,
    NoStateChange,
}

enum Outcome {
    Applied(ModelState),
    Rejected(Rejection),
}

fn apply(state: &ModelState, action: Action) -> Outcome {
    if let Some(candidate) = action.candidate() {
        return promote(state, candidate);
    }

    let mut next = state.clone();
    let changed = match action {
        Action::PartitionA => set_connection(&mut next, Node::A, false),
        Action::HealA => set_connection(&mut next, Node::A, true),
        Action::PartitionB => set_connection(&mut next, Node::B, false),
        Action::HealB => set_connection(&mut next, Node::B, true),
        Action::StopWitness => set_bool(&mut next.witness_up, false),
        Action::StartWitness => set_bool(&mut next.witness_up, true),
        Action::CrashA => crash(&mut next, Node::A),
        Action::RestartA => restart(&mut next, Node::A),
        Action::CrashB => crash(&mut next, Node::B),
        Action::RestartB => restart(&mut next, Node::B),
        Action::FenceA => fence(&mut next, Node::A),
        Action::FenceB => fence(&mut next, Node::B),
        Action::LagA => set_caught_up(&mut next, Node::A, false),
        Action::CatchUpA => set_caught_up(&mut next, Node::A, true),
        Action::LagB => set_caught_up(&mut next, Node::B, false),
        Action::CatchUpB => set_caught_up(&mut next, Node::B, true),
        Action::AdvanceTime => {
            let Some(value) = next.now_tick.checked_add(1) else {
                return Outcome::Rejected(Rejection::NoStateChange);
            };
            next.now_tick = value;
            true
        }
        Action::PromoteA | Action::PromoteB => false,
    };
    if changed {
        Outcome::Applied(next)
    } else {
        Outcome::Rejected(Rejection::NoStateChange)
    }
}

fn promote(state: &ModelState, candidate: Node) -> Outcome {
    let candidate_state = state.node(candidate);
    if !candidate_state.powered || candidate_state.fenced {
        return Outcome::Rejected(Rejection::CandidateUnavailable);
    }
    if !candidate_state.connected_to_witness || !state.witness_up {
        return Outcome::Rejected(Rejection::NoQuorum);
    }
    if candidate_state.gate_is_effective(state.now_tick) {
        return Outcome::Rejected(Rejection::AlreadyEffective);
    }

    let Some(new_epoch) = state.epoch.checked_add(1) else {
        return Outcome::Rejected(Rejection::NoStateChange);
    };
    let Some(expires_at_tick) = state.now_tick.checked_add(3) else {
        return Outcome::Rejected(Rejection::NoStateChange);
    };
    let now_ms = u64::from(state.now_tick) * 100;
    let expires_at_ms = u64::from(expires_at_tick) * 100;
    let candidate_id = model_node_id(candidate);
    let witness_id = model_witness_id();
    let workload = model_workload();
    let policy_hash = model_policy_hash();
    let required_commit = CommitIndex(10);
    let state_root = StateRoot::new([1; 32]);
    let current = AuthorityState {
        epoch: Epoch(state.epoch),
        holder: state.metadata_holder.map(model_node_id),
        lease_expires_at_ms: state
            .metadata_lease_expires_at_tick
            .map(|tick| u64::from(tick) * 100),
    };
    let (target, mechanism) = match state.metadata_holder {
        None => (None, FenceMechanism::Bootstrap),
        Some(holder) => {
            let mechanism = if state.node(holder).fenced {
                FenceMechanism::HardwarePower
            } else {
                FenceMechanism::EffectGateExpired
            };
            (Some(model_node_id(holder)), mechanism)
        }
    };
    let incarnation = Incarnation(candidate_state.incarnation);
    let proof = PromotionProof {
        workload: workload.clone(),
        candidate: candidate_id.clone(),
        candidate_incarnation: incarnation,
        epoch: Epoch(new_epoch),
        policy_hash,
        quorum: QuorumCertificate {
            epoch: Epoch(new_epoch),
            workload: workload.clone(),
            candidate: candidate_id.clone(),
            candidate_incarnation: incarnation,
            policy_hash,
            required_commit,
            state_root,
            lease_not_before_ms: now_ms,
            lease_expires_at_ms: expires_at_ms,
            voters: vec![candidate_id.clone(), witness_id.clone()],
        },
        fence: FenceReceipt {
            epoch: Epoch(new_epoch),
            target,
            verifier: witness_id.clone(),
            mechanism,
            observed_at_ms: now_ms,
        },
        state: StateEvidence {
            required_commit,
            durable_commit: if candidate_state.caught_up {
                required_commit
            } else {
                CommitIndex(9)
            },
            state_root,
            observed_at_ms: now_ms,
        },
        health: HealthAttestation {
            workload: workload.clone(),
            node: candidate_id.clone(),
            incarnation,
            epoch: Epoch(new_epoch),
            healthy: candidate_state.powered,
            passed_checks: 3,
            observed_at_ms: now_ms,
        },
        lease: LeaseGrant {
            workload: workload.clone(),
            holder: candidate_id.clone(),
            incarnation,
            epoch: Epoch(new_epoch),
            not_before_ms: now_ms,
            expires_at_ms,
        },
    };
    let policy_result = SafetyPolicy::new(
        workload.clone(),
        policy_hash,
        [model_node_id(Node::A), model_node_id(Node::B)],
        [model_node_id(Node::A), model_node_id(Node::B), witness_id],
        2,
        Some(model_witness_id()),
        3,
        500,
        300,
        100,
        true,
    );
    let Ok(policy) = policy_result else {
        return Outcome::Rejected(Rejection::CoreRefused);
    };
    let authorization = match validate_promotion(&proof, &current, &policy, now_ms) {
        Ok(authorization) => authorization,
        Err(ProofError::CandidateStateBehind) => {
            return Outcome::Rejected(Rejection::CandidateBehind);
        }
        Err(ProofError::FenceGuardNotElapsed) => {
            return Outcome::Rejected(Rejection::OldGateEffective);
        }
        Err(ProofError::CandidateAlreadyHoldsAuthority) => {
            return Outcome::Rejected(Rejection::AlreadyEffective);
        }
        Err(_) => return Outcome::Rejected(Rejection::CoreRefused),
    };

    let clock = ModelClock(now_ms);
    let recovery =
        GateRecoveryState::new(Epoch(candidate_state.accepted_epoch), incarnation, now_ms);
    let mut gate =
        EffectGate::recover(candidate_id.clone(), workload, policy_hash, recovery, clock);
    let record = match gate.stage(authorization) {
        Ok(record) => record,
        Err(_) => return Outcome::Rejected(Rejection::CoreRefused),
    };
    if gate.confirm_persisted(&record).is_err()
        || gate.activate().is_err()
        || gate.check_effect(&candidate_id, Epoch(new_epoch)).is_err()
    {
        return Outcome::Rejected(Rejection::CoreRefused);
    }

    let mut next = state.clone();
    next.epoch = new_epoch;
    next.metadata_holder = Some(candidate);
    next.metadata_lease_expires_at_tick = Some(expires_at_tick);
    let node = next.node_mut(candidate);
    node.accepted_epoch = new_epoch;
    node.gate = Some(GateLease {
        epoch: new_epoch,
        incarnation: candidate_state.incarnation,
        expires_at_tick,
    });
    Outcome::Applied(next)
}

fn set_bool(target: &mut bool, value: bool) -> bool {
    let changed = *target != value;
    *target = value;
    changed
}

fn set_connection(state: &mut ModelState, node: Node, connected: bool) -> bool {
    set_bool(&mut state.node_mut(node).connected_to_witness, connected)
}

fn set_caught_up(state: &mut ModelState, node: Node, caught_up: bool) -> bool {
    set_bool(&mut state.node_mut(node).caught_up, caught_up)
}

fn crash(state: &mut ModelState, node: Node) -> bool {
    let node = state.node_mut(node);
    if !node.powered {
        return false;
    }
    node.powered = false;
    node.gate = None;
    true
}

fn restart(state: &mut ModelState, node: Node) -> bool {
    let node = state.node_mut(node);
    if node.powered || node.fenced {
        return false;
    }
    let Some(incarnation) = node.incarnation.checked_add(1) else {
        return false;
    };
    node.powered = true;
    node.connected_to_witness = true;
    node.incarnation = incarnation;
    node.gate = None;
    true
}

#[derive(Clone, Copy)]
struct ModelClock(u64);

impl TrustedClock for ModelClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

fn model_node_id(node: Node) -> NodeId {
    let value = match node {
        Node::A => "node-a",
        Node::B => "node-b",
    };
    let Ok(identifier) = NodeId::new(value) else {
        std::process::abort();
    };
    identifier
}

fn model_witness_id() -> NodeId {
    let Ok(identifier) = NodeId::new("witness") else {
        std::process::abort();
    };
    identifier
}

fn model_workload() -> WorkloadId {
    let Ok(identifier) = WorkloadId::new("model-workload") else {
        std::process::abort();
    };
    identifier
}

const fn model_policy_hash() -> PolicyHash {
    PolicyHash::new([5; 32])
}

fn fence(state: &mut ModelState, node: Node) -> bool {
    let node = state.node_mut(node);
    let changed = !node.fenced || node.powered || node.gate.is_some();
    node.fenced = true;
    node.powered = false;
    node.gate = None;
    changed
}

/// A reachable state that violated the single-writer invariant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    /// Reproducible action sequence.
    pub trace: Vec<Action>,
    /// Number of simultaneously effective writers.
    pub active_writers: usize,
}

/// Deterministic state-space exploration summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationReport {
    /// Maximum action depth requested.
    pub depth: usize,
    /// Unique states reached across all layers.
    pub states_explored: usize,
    /// Applied state transitions inspected.
    pub transitions_explored: usize,
    /// Promotion requests refused by a safety precondition.
    pub rejected_promotions: usize,
    /// Single-writer invariant failures.
    pub violations: Vec<Violation>,
}

impl SimulationReport {
    /// Whether no invariant violation was found in the explored state space.
    #[must_use]
    pub fn is_safe(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Exhaustively explores all compact-model action interleavings up to `depth`.
#[must_use]
pub fn explore(depth: usize) -> SimulationReport {
    let initial = ModelState::default();
    let mut seen = BTreeMap::from([(initial.clone(), Vec::<Action>::new())]);
    let mut frontier = BTreeMap::from([(initial, Vec::<Action>::new())]);
    let mut transitions_explored = 0;
    let mut rejected_promotions = 0;
    let mut violations = Vec::new();

    for _ in 0..depth {
        let mut next_frontier = BTreeMap::new();
        for (state, trace) in frontier {
            for action in Action::ALL {
                match apply(&state, action) {
                    Outcome::Applied(next) => {
                        transitions_explored += 1;
                        let mut next_trace = trace.clone();
                        next_trace.push(action);
                        let active_writers = next.active_writers();
                        if active_writers > 1 {
                            violations.push(Violation {
                                trace: next_trace.clone(),
                                active_writers,
                            });
                        }
                        if let Entry::Vacant(entry) = seen.entry(next.clone()) {
                            entry.insert(next_trace.clone());
                            next_frontier.insert(next, next_trace);
                        }
                    }
                    Outcome::Rejected(reason) => {
                        if action.candidate().is_some()
                            && !matches!(reason, Rejection::NoStateChange)
                        {
                            rejected_promotions += 1;
                        }
                    }
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    SimulationReport {
        depth,
        states_explored: seen.len(),
        transitions_explored,
        rejected_promotions,
        violations,
    }
}

/// Result of bounded pseudo-random Monte Carlo scenario exploration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SeededSimulationReport {
    /// Seed used for pseudo-random schedule generation.
    pub seed: u64,
    /// Number of distinct scenario paths evaluated.
    pub scenarios: u64,
    /// Maximum steps per scenario path.
    pub max_steps: usize,
    /// Total delayed events delivered across all scenarios.
    pub steps_executed: u64,
    /// Events delivered ahead of an earlier-created delayed event.
    pub reordered_events: u64,
    /// Promotions refused by safety preconditions.
    pub rejected_promotions: u64,
    /// 64-bit digest of the generated deterministic schedule.
    pub schedule_digest: u64,
    /// First violating trace, if any single-writer invariant was broken.
    pub first_violation: Option<Violation>,
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ScheduledEvent {
    deliver_at_tick: u8,
    schedule_seq: u64,
    action: Action,
}

/// Runs deterministic pseudo-random Monte Carlo scenarios up to `scenarios` count.
#[must_use]
pub fn run_seeded_scenarios(seed: u64, scenarios: u64, max_steps: usize) -> SeededSimulationReport {
    let mut prng = SplitMix64::new(seed);
    let mut steps_executed = 0_u64;
    let mut reordered_events = 0_u64;
    let mut rejected_promotions = 0_u64;
    let mut schedule_digest = 0_u64;
    let mut first_violation = None;

    for _ in 0..scenarios {
        let mut state = ModelState::default();
        let mut trace = Vec::with_capacity(max_steps);
        let mut pending: Vec<ScheduledEvent> = Vec::with_capacity(8);
        let mut seq = 0_u64;

        for step in 0..max_steps {
            let choice = (prng.next_u64() % (Action::ALL.len() as u64)) as usize;
            let action = Action::ALL[choice];
            schedule_digest = schedule_digest
                .rotate_left(5)
                .bitxor(u64::from(choice as u8));

            let delay = match action {
                Action::PartitionA
                | Action::PartitionB
                | Action::HealA
                | Action::HealB
                | Action::LagA
                | Action::LagB
                | Action::CatchUpA
                | Action::CatchUpB => (prng.next_u64() % 3) as u8,
                Action::PromoteA | Action::PromoteB => 0,
                Action::AdvanceTime => 0,
                _ => (prng.next_u64() % 2) as u8,
            };

            seq = seq.wrapping_add(1);
            let deliver_at_tick = state.now_tick.saturating_add(delay);
            pending.push(ScheduledEvent {
                deliver_at_tick,
                schedule_seq: seq,
                action,
            });

            if action == Action::AdvanceTime
                || pending.len() >= 4
                || step == max_steps.saturating_sub(1)
            {
                pending.sort_by(|a, b| {
                    b.deliver_at_tick
                        .cmp(&a.deliver_at_tick)
                        .then_with(|| b.schedule_seq.cmp(&a.schedule_seq))
                });
                for left in 0..pending.len() {
                    for right in left.saturating_add(1)..pending.len() {
                        if pending[left].schedule_seq < pending[right].schedule_seq {
                            reordered_events = reordered_events.saturating_add(1);
                        }
                    }
                }
                while let Some(event) = pending.pop() {
                    match apply(&state, event.action) {
                        Outcome::Applied(next) => {
                            steps_executed = steps_executed.saturating_add(1);
                            trace.push(event.action);
                            let active_writers = next.active_writers();
                            if active_writers > 1 {
                                if first_violation.is_none() {
                                    first_violation = Some(Violation {
                                        trace: trace.clone(),
                                        active_writers,
                                    });
                                }
                                break;
                            }
                            state = next;
                        }
                        Outcome::Rejected(reason) => {
                            if event.action.candidate().is_some()
                                && !matches!(reason, Rejection::NoStateChange)
                            {
                                rejected_promotions = rejected_promotions.saturating_add(1);
                            }
                        }
                    }
                }
            }
            if first_violation.is_some() {
                break;
            }
        }
        if first_violation.is_some() {
            break;
        }
    }

    SeededSimulationReport {
        seed,
        scenarios,
        max_steps,
        steps_executed,
        reordered_events,
        rejected_promotions,
        schedule_digest,
        first_violation,
    }
}

use std::ops::BitXor;

#[cfg(test)]
mod tests {
    use super::*;

    fn applied(state: &ModelState, action: Action) -> ModelState {
        match apply(state, action) {
            Outcome::Applied(next) => next,
            Outcome::Rejected(_) => std::process::abort(),
        }
    }

    #[test]
    fn exhaustive_compact_model_preserves_single_writer() {
        let report = explore(9);
        assert!(report.states_explored > 100);
        assert!(report.transitions_explored > report.states_explored);
        assert!(report.is_safe());
    }

    #[test]
    fn partition_and_quorum_do_not_bypass_old_gate() {
        let state = applied(&ModelState::default(), Action::PromoteA);
        let state = applied(&state, Action::PartitionA);
        assert!(matches!(
            apply(&state, Action::PromoteB),
            Outcome::Rejected(Rejection::OldGateEffective)
        ));
    }

    #[test]
    fn promotion_succeeds_after_old_lease_expiry() {
        let mut state = applied(&ModelState::default(), Action::PromoteA);
        state = applied(&state, Action::PartitionA);
        state = applied(&state, Action::AdvanceTime);
        state = applied(&state, Action::AdvanceTime);
        state = applied(&state, Action::AdvanceTime);
        state = applied(&state, Action::AdvanceTime);
        state = applied(&state, Action::PromoteB);
        assert_eq!(state.active_writers(), 1);
        assert_eq!(state.epoch(), 2);
    }

    #[test]
    fn invariant_detector_rejects_counterfactual_dual_gate() {
        let mut state = applied(&ModelState::default(), Action::PromoteA);
        state.b.gate = Some(GateLease {
            epoch: 2,
            incarnation: state.b.incarnation,
            expires_at_tick: 3,
        });
        assert_eq!(state.active_writers(), 2);
    }

    #[test]
    fn seeded_scenarios_replay_exactly_and_respect_requested_bound() {
        let first = run_seeded_scenarios(0x5eed, 10_000, 24);
        let second = run_seeded_scenarios(0x5eed, 10_000, 24);

        assert_eq!(first, second);
        assert_eq!(first.scenarios, 10_000);
        assert!(first.steps_executed <= 240_000);
        assert_eq!(first.first_violation, None);
    }

    #[test]
    fn different_seed_changes_schedule_digest() {
        let first = run_seeded_scenarios(11, 1_000, 16);
        let second = run_seeded_scenarios(12, 1_000, 16);

        assert_ne!(first.schedule_digest, second.schedule_digest);
    }
}
