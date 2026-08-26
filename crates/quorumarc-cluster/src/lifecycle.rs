use std::fs;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer};
use quorumarc_core::{
    AuthorityState as CoreAuthorityState, CommitIndex, EffectGate, Epoch,
    FenceMechanism as CoreFenceMechanism, FenceReceipt as CoreFenceReceipt, GateRecoveryState,
    HealthAttestation as CoreHealthAttestation, Incarnation, LeaseGrant as CoreLeaseGrant, NodeId,
    PolicyHash, PromotionProof as CorePromotionProof, QuorumCertificate as CoreQuorumCertificate,
    SafetyPolicy, StateEvidence, StateRoot as CoreStateRoot, TrustedClock, WorkloadId,
    validate_promotion,
};
use quorumarc_rpo0::{OperationId, WalEntry, recover_wal};
use quorumarc_runtime::{
    EffectOutcome, FrameCodec, TestEffectActor, VoteReasonCode, WitnessPolicy, WitnessVoteActor,
};
use quorumarc_store::{
    ActivationReceipt, DurableAuthorityStore, FaultInjectingBackend, FaultMode, FaultOperation,
    FaultRule, FileBackend, LeaseBounds, PromotionRecord, StateRoot as StoreStateRoot,
    StoreIdentity, StoreRole, VoteRecord,
};
use quorumarc_wire::{
    CanonicalId, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant, MessageId,
    PROTOCOL_VERSION, PromotionEnvelope, QuorumBinding, QuorumCertificate, SignedPromotionEnvelope,
    SignedVote, SigningKey, VerificationKeyResolver, VerifyingKey,
};
use sha2::{Digest, Sha256};

use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::path_guard::{
    OwnerLock, prepare_file_parent, prepare_store_directory, require_disjoint_store_and_file,
    require_keys_disjoint, require_ready_disjoint, write_ready_file,
};
use crate::protocol::{
    MAX_CLUSTER_FRAME, WitnessDecision, WitnessResponse, id, witness_request_digest,
};
use crate::{ClusterError, err};

const LIFECYCLE_CLUSTER: &str = "gate1a-lifecycle";
const LIFECYCLE_WORKLOAD: &str = "orders";
const LIFECYCLE_WITNESS: &str = "witness";
const LIFECYCLE_KEY_ID: &str = "key-1";
const NODE_A: &str = "node-a";
const NODE_B: &str = "node-b";
const POLICY_HASH: [u8; 32] = [0xa5; 32];
const REQUIRED_COMMIT: u64 = 1;
const LEASE_BASE_MS: u64 = 1_000;
const LEASE_DURATION_MS: u64 = 200;
const LEASE_GUARD_MS: u64 = 50;
const LEASE_STRIDE_MS: u64 = LEASE_DURATION_MS + LEASE_GUARD_MS;
const MAX_LIFECYCLE_FRAME: usize = 4_096;
const COMMAND_MAGIC: &[u8; 8] = b"QALCMD\0\0";
const RESPONSE_MAGIC: &[u8; 8] = b"QALRSP\0\0";
const COMMAND_DOMAIN: &[u8] = b"quorumarc/lifecycle/command/ed25519/v1\0";
const RESPONSE_DOMAIN: &[u8] = b"quorumarc/lifecycle/response/ed25519/v1\0";
const MESSAGE_ID_DOMAIN: &[u8] = b"quorumarc/lifecycle/message-id/sha256/v1\0";
const FENCE_EVIDENCE_DOMAIN: &[u8] = b"quorumarc/lifecycle/fence-evidence/sha256/v1\0";
const RESPONSE_UNSIGNED_LEN: usize = 110;
const RESPONSE_LEN: usize = RESPONSE_UNSIGNED_LEN + 64;
const COMMAND_UNSIGNED_LEN: usize = 60;
const COMMAND_LEN: usize = COMMAND_UNSIGNED_LEN + 64;

/// Workload-capable identity used by the bounded lifecycle laboratory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleNodeId {
    /// First data-node identity.
    NodeA,
    /// Second data-node identity.
    NodeB,
}

impl LifecycleNodeId {
    /// Parses the only two workload-capable lifecycle identities.
    pub fn parse(value: &str) -> Result<Self, ClusterError> {
        match value {
            NODE_A => Ok(Self::NodeA),
            NODE_B => Ok(Self::NodeB),
            _ => Err(err(
                "LIFECYCLE_NODE_ID_REFUSED",
                "node identity must be node-a or node-b",
            )),
        }
    }

    /// Stable node identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeA => NODE_A,
            Self::NodeB => NODE_B,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::NodeA => 1,
            Self::NodeB => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::NodeA),
            2 => Ok(Self::NodeB),
            _ => Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "unknown lifecycle node tag",
            )),
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::NodeA => Self::NodeB,
            Self::NodeB => Self::NodeA,
        }
    }
}

/// Observable node role in the bounded lifecycle controller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    Booting,
    Standby,
    Candidate,
    Active,
    Draining,
    SelfFenced,
}

impl LifecycleState {
    /// Stable structured-log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Booting => "BOOTING",
            Self::Standby => "STANDBY",
            Self::Candidate => "CANDIDATE",
            Self::Active => "ACTIVE",
            Self::Draining => "DRAINING",
            Self::SelfFenced => "SELF_FENCED",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Booting => 1,
            Self::Standby => 2,
            Self::Candidate => 3,
            Self::Active => 4,
            Self::Draining => 5,
            Self::SelfFenced => 6,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Booting),
            2 => Ok(Self::Standby),
            3 => Ok(Self::Candidate),
            4 => Ok(Self::Active),
            5 => Ok(Self::Draining),
            6 => Ok(Self::SelfFenced),
            _ => Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "unknown lifecycle state tag",
            )),
        }
    }
}

/// Stable result of one lifecycle control request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleReasonCode {
    Status,
    Promoted,
    TickApplied,
    EffectRecorded,
    EffectAlreadyRecorded,
    Closed,
    Stopping,
    RefusedLeaseNotActive,
    RefusedWitnessUnavailable,
    RefusedWitnessVote,
    RefusedCandidateLagging,
    RefusedPolicy,
    RefusedEpoch,
    RefusedDurability,
    RefusedProof,
    RefusedGate,
    RefusedNotActive,
    RefusedAlreadyActive,
    RefusedClockRollback,
    RefusedTerminalFault,
    RefusedReplay,
}

impl LifecycleReasonCode {
    /// Stable machine-readable decision spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status => "LIFECYCLE_STATUS",
            Self::Promoted => "LIFECYCLE_PROMOTED",
            Self::TickApplied => "LIFECYCLE_TICK_APPLIED",
            Self::EffectRecorded => "LIFECYCLE_EFFECT_RECORDED",
            Self::EffectAlreadyRecorded => "LIFECYCLE_EFFECT_ALREADY_RECORDED",
            Self::Closed => "LIFECYCLE_CLOSED",
            Self::Stopping => "LIFECYCLE_STOPPING",
            Self::RefusedLeaseNotActive => "LIFECYCLE_REFUSED_LEASE_NOT_ACTIVE",
            Self::RefusedWitnessUnavailable => "LIFECYCLE_REFUSED_WITNESS_UNAVAILABLE",
            Self::RefusedWitnessVote => "LIFECYCLE_REFUSED_WITNESS_VOTE",
            Self::RefusedCandidateLagging => "LIFECYCLE_REFUSED_CANDIDATE_LAGGING",
            Self::RefusedPolicy => "LIFECYCLE_REFUSED_POLICY",
            Self::RefusedEpoch => "LIFECYCLE_REFUSED_EPOCH",
            Self::RefusedDurability => "LIFECYCLE_REFUSED_DURABILITY",
            Self::RefusedProof => "LIFECYCLE_REFUSED_PROOF",
            Self::RefusedGate => "LIFECYCLE_REFUSED_GATE",
            Self::RefusedNotActive => "LIFECYCLE_REFUSED_NOT_ACTIVE",
            Self::RefusedAlreadyActive => "LIFECYCLE_REFUSED_ALREADY_ACTIVE",
            Self::RefusedClockRollback => "LIFECYCLE_REFUSED_CLOCK_ROLLBACK",
            Self::RefusedTerminalFault => "LIFECYCLE_REFUSED_TERMINAL_FAULT",
            Self::RefusedReplay => "LIFECYCLE_REFUSED_REPLAY",
        }
    }

    const fn tag(self) -> u16 {
        match self {
            Self::Status => 1,
            Self::Promoted => 2,
            Self::TickApplied => 3,
            Self::EffectRecorded => 4,
            Self::EffectAlreadyRecorded => 5,
            Self::Closed => 6,
            Self::Stopping => 7,
            Self::RefusedLeaseNotActive => 100,
            Self::RefusedWitnessUnavailable => 101,
            Self::RefusedWitnessVote => 102,
            Self::RefusedCandidateLagging => 103,
            Self::RefusedPolicy => 104,
            Self::RefusedEpoch => 105,
            Self::RefusedDurability => 106,
            Self::RefusedProof => 107,
            Self::RefusedGate => 108,
            Self::RefusedNotActive => 109,
            Self::RefusedAlreadyActive => 110,
            Self::RefusedClockRollback => 111,
            Self::RefusedTerminalFault => 112,
            Self::RefusedReplay => 113,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Status),
            2 => Ok(Self::Promoted),
            3 => Ok(Self::TickApplied),
            4 => Ok(Self::EffectRecorded),
            5 => Ok(Self::EffectAlreadyRecorded),
            6 => Ok(Self::Closed),
            7 => Ok(Self::Stopping),
            100 => Ok(Self::RefusedLeaseNotActive),
            101 => Ok(Self::RefusedWitnessUnavailable),
            102 => Ok(Self::RefusedWitnessVote),
            103 => Ok(Self::RefusedCandidateLagging),
            104 => Ok(Self::RefusedPolicy),
            105 => Ok(Self::RefusedEpoch),
            106 => Ok(Self::RefusedDurability),
            107 => Ok(Self::RefusedProof),
            108 => Ok(Self::RefusedGate),
            109 => Ok(Self::RefusedNotActive),
            110 => Ok(Self::RefusedAlreadyActive),
            111 => Ok(Self::RefusedClockRollback),
            112 => Ok(Self::RefusedTerminalFault),
            113 => Ok(Self::RefusedReplay),
            _ => Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "unknown lifecycle reason code",
            )),
        }
    }

    /// Whether this response confirms an externally effective writer.
    #[must_use]
    pub const fn effect_succeeded(self) -> bool {
        matches!(self, Self::EffectRecorded | Self::EffectAlreadyRecorded)
    }
}

/// Deterministic store failure used only by bounded lifecycle fault tests.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum LifecycleStoreFault {
    #[default]
    None,
    PromotionWriteError,
    PromotionPartialWrite,
}

/// Long-running lifecycle data-node service settings.
#[derive(Clone, Debug)]
pub struct LifecycleNodeConfig {
    pub node_id: LifecycleNodeId,
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub wal_path: PathBuf,
    pub store_directory: PathBuf,
    pub signing_key_file: PathBuf,
    pub witness_public_key_file: PathBuf,
    pub controller_public_key_file: PathBuf,
    pub witness_address: SocketAddr,
    pub max_connections: u64,
    pub io_timeout: Duration,
    pub policy_hash: [u8; 32],
    pub store_fault: LifecycleStoreFault,
}

/// Long-running independent lifecycle Witness settings.
#[derive(Clone, Debug)]
pub struct LifecycleWitnessConfig {
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub store_directory: PathBuf,
    pub signing_key_file: PathBuf,
    pub node_a_public_key_file: PathBuf,
    pub node_b_public_key_file: PathBuf,
    pub max_connections: u64,
    pub io_timeout: Duration,
    pub policy_hash: [u8; 32],
}

/// Authenticated response returned by a lifecycle node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReport {
    pub node_id: LifecycleNodeId,
    pub reason_code: LifecycleReasonCode,
    pub state: LifecycleState,
    pub highest_epoch: u64,
    pub incarnation: u64,
    pub store_generation: u64,
    pub effect_count: u64,
    pub commit_index: u64,
    pub state_root: [u8; 32],
    pub lease_expires_at_ms: u64,
}

/// Stable reason emitted by the deterministic automatic-failover state
/// machine. These reasons are decisions only; they never grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAutoReason {
    WaitingForFailureThreshold,
    WaitingForLeaseGuard,
    WitnessUnavailable,
    CandidateUnavailable,
    CandidateLagging,
    PromotionPending,
    PromotionWindowMissed,
    AmbiguousActive,
}

/// One bounded automatic-failover state-machine decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleAutoDecision {
    Stable {
        active: LifecycleNodeId,
        epoch: u64,
    },
    Hold {
        reason: LifecycleAutoReason,
    },
    Promote {
        candidate: LifecycleNodeId,
        epoch: u64,
    },
    Halt {
        reason: LifecycleAutoReason,
    },
}

#[derive(Clone, Copy)]
struct ObservedActive {
    node: LifecycleNodeId,
    epoch: u64,
    lease_expires_at_ms: u64,
}

/// Deterministic lab-only automatic failover state machine.
///
/// Signed status reports are supplied by authenticated `LifecycleClient`
/// calls. Loss of a report only advances failure suspicion. It never acts as a
/// fence: promotion is emitted only in the next fixed lease window, and the
/// candidate must still obtain a durable Witness vote and pass EffectGate.
pub struct LifecycleAutoController {
    failure_threshold: u32,
    active_misses: u32,
    last_active: Option<ObservedActive>,
    pending: Option<(LifecycleNodeId, u64)>,
    halted: Option<LifecycleAutoReason>,
}

impl LifecycleAutoController {
    /// Creates a bounded controller. Requiring more than one failed probe
    /// prevents a single transient status failure from becoming a failover
    /// attempt.
    pub fn new(failure_threshold: u32) -> Result<Self, ClusterError> {
        if !(2..=16).contains(&failure_threshold) {
            return Err(err(
                "LIFECYCLE_AUTO_POLICY_REFUSED",
                "failure threshold must be between 2 and 16",
            ));
        }
        Ok(Self {
            failure_threshold,
            active_misses: 0,
            last_active: None,
            pending: None,
            halted: None,
        })
    }

    /// Evaluates one pair of fresh signed node observations.
    pub fn evaluate(
        &mut self,
        now_ms: u64,
        node_a: Option<&LifecycleReport>,
        node_b: Option<&LifecycleReport>,
        witness_available: bool,
    ) -> Result<LifecycleAutoDecision, ClusterError> {
        validate_auto_report(node_a, LifecycleNodeId::NodeA)?;
        validate_auto_report(node_b, LifecycleNodeId::NodeB)?;
        if let Some(reason) = self.halted {
            return Ok(LifecycleAutoDecision::Halt { reason });
        }

        let active_a = node_a.filter(|report| report.state == LifecycleState::Active);
        let active_b = node_b.filter(|report| report.state == LifecycleState::Active);
        if active_a.is_some() && active_b.is_some() {
            self.halted = Some(LifecycleAutoReason::AmbiguousActive);
            return Ok(LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::AmbiguousActive,
            });
        }
        if let Some(report) = active_a.or(active_b) {
            let active = active_from_report(report)?;
            if let Some(previous) = self.last_active {
                if active.epoch < previous.epoch
                    || (active.epoch == previous.epoch && active.node != previous.node)
                {
                    self.halted = Some(LifecycleAutoReason::AmbiguousActive);
                    return Ok(LifecycleAutoDecision::Halt {
                        reason: LifecycleAutoReason::AmbiguousActive,
                    });
                }
            }
            self.last_active = Some(active);
            self.active_misses = 0;
            self.pending = None;
            if now_ms < active.lease_expires_at_ms {
                return Ok(LifecycleAutoDecision::Stable {
                    active: active.node,
                    epoch: active.epoch,
                });
            }
        }

        if self.pending.is_some() {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::PromotionPending,
            });
        }
        let Some(previous) = self.last_active else {
            return self.bootstrap_decision(now_ms, node_a, node_b, witness_available);
        };

        let prior_observation = match previous.node {
            LifecycleNodeId::NodeA => node_a,
            LifecycleNodeId::NodeB => node_b,
        };
        if prior_observation.is_none() {
            self.active_misses = self.active_misses.saturating_add(1);
        } else if prior_observation.is_some_and(|report| {
            matches!(
                report.state,
                LifecycleState::SelfFenced | LifecycleState::Draining
            )
        }) {
            self.active_misses = self.failure_threshold;
        }
        if self.active_misses < self.failure_threshold {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForFailureThreshold,
            });
        }

        let epoch = previous
            .epoch
            .checked_add(1)
            .ok_or_else(|| err("LIFECYCLE_AUTO_EPOCH_EXHAUSTED", "epoch overflow"))?;
        let (window_start, window_end) = lease_for_epoch(epoch)?;
        if now_ms < window_start {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            });
        }
        if now_ms >= window_end {
            self.halted = Some(LifecycleAutoReason::PromotionWindowMissed);
            return Ok(LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::PromotionWindowMissed,
            });
        }
        if !witness_available {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WitnessUnavailable,
            });
        }
        let candidate = previous.node.other();
        let candidate_report = match candidate {
            LifecycleNodeId::NodeA => node_a,
            LifecycleNodeId::NodeB => node_b,
        }
        .ok_or(LifecycleAutoDecision::Hold {
            reason: LifecycleAutoReason::CandidateUnavailable,
        });
        let candidate_report = match candidate_report {
            Ok(report) => report,
            Err(decision) => return Ok(decision),
        };
        if !eligible_standby(candidate_report)? {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateLagging,
            });
        }
        self.pending = Some((candidate, epoch));
        Ok(LifecycleAutoDecision::Promote { candidate, epoch })
    }

    /// Records the signed result of the exact promotion attempt returned by
    /// `evaluate`. A refusal clears the pending attempt but grants nothing.
    pub fn record_promotion_result(
        &mut self,
        report: &LifecycleReport,
    ) -> Result<(), ClusterError> {
        let Some((candidate, epoch)) = self.pending else {
            return Err(err(
                "LIFECYCLE_AUTO_RESULT_REFUSED",
                "no promotion attempt is pending",
            ));
        };
        if report.node_id != candidate || report.highest_epoch > epoch {
            self.halted = Some(LifecycleAutoReason::AmbiguousActive);
            return Err(err(
                "LIFECYCLE_AUTO_RESULT_REFUSED",
                "promotion result does not match the pending candidate and epoch",
            ));
        }
        self.pending = None;
        if report.reason_code == LifecycleReasonCode::Promoted
            && report.state == LifecycleState::Active
        {
            let active = active_from_report(report)?;
            if active.epoch != epoch {
                self.halted = Some(LifecycleAutoReason::AmbiguousActive);
                return Err(err(
                    "LIFECYCLE_AUTO_RESULT_REFUSED",
                    "promotion result epoch differs from pending epoch",
                ));
            }
            self.last_active = Some(active);
            self.active_misses = 0;
        }
        Ok(())
    }

    fn bootstrap_decision(
        &mut self,
        now_ms: u64,
        node_a: Option<&LifecycleReport>,
        node_b: Option<&LifecycleReport>,
        witness_available: bool,
    ) -> Result<LifecycleAutoDecision, ClusterError> {
        let (window_start, window_end) = lease_for_epoch(1)?;
        if now_ms < window_start {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WaitingForLeaseGuard,
            });
        }
        if now_ms >= window_end {
            self.halted = Some(LifecycleAutoReason::PromotionWindowMissed);
            return Ok(LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::PromotionWindowMissed,
            });
        }
        if !witness_available {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::WitnessUnavailable,
            });
        }
        let (Some(node_a), Some(node_b)) = (node_a, node_b) else {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateUnavailable,
            });
        };
        if !eligible_standby(node_a)? || !eligible_standby(node_b)? {
            return Ok(LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateLagging,
            });
        }
        self.pending = Some((LifecycleNodeId::NodeA, 1));
        Ok(LifecycleAutoDecision::Promote {
            candidate: LifecycleNodeId::NodeA,
            epoch: 1,
        })
    }
}

fn validate_auto_report(
    report: Option<&LifecycleReport>,
    expected_node: LifecycleNodeId,
) -> Result<(), ClusterError> {
    if report.is_some_and(|report| report.node_id != expected_node) {
        return Err(err(
            "LIFECYCLE_AUTO_REPORT_REFUSED",
            "signed status was supplied under the wrong node slot",
        ));
    }
    Ok(())
}

fn active_from_report(report: &LifecycleReport) -> Result<ObservedActive, ClusterError> {
    if report.highest_epoch == 0 || report.lease_expires_at_ms == 0 {
        return Err(err(
            "LIFECYCLE_AUTO_REPORT_REFUSED",
            "Active report has no epoch or lease expiry",
        ));
    }
    let (_, expected_expiry) = lease_for_epoch(report.highest_epoch)?;
    if report.lease_expires_at_ms != expected_expiry {
        return Err(err(
            "LIFECYCLE_AUTO_REPORT_REFUSED",
            "Active report lease differs from the pinned epoch schedule",
        ));
    }
    Ok(ObservedActive {
        node: report.node_id,
        epoch: report.highest_epoch,
        lease_expires_at_ms: report.lease_expires_at_ms,
    })
}

fn eligible_standby(report: &LifecycleReport) -> Result<bool, ClusterError> {
    Ok(report.state == LifecycleState::Standby
        && report.commit_index >= REQUIRED_COMMIT
        && report.state_root == expected_state_root()?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CommandKind {
    Status,
    Promote,
    Tick,
    Emit,
    Close,
    Stop,
    Replay,
}

impl CommandKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Status => 1,
            Self::Promote => 2,
            Self::Tick => 3,
            Self::Emit => 4,
            Self::Close => 5,
            Self::Stop => 6,
            Self::Replay => 7,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Status),
            2 => Ok(Self::Promote),
            3 => Ok(Self::Tick),
            4 => Ok(Self::Emit),
            5 => Ok(Self::Close),
            6 => Ok(Self::Stop),
            7 => Ok(Self::Replay),
            _ => Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "unknown lifecycle command tag",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LifecycleCommand {
    request_id: [u8; 16],
    kind: CommandKind,
    now_ms: u64,
    epoch: u64,
    operation_id: [u8; 16],
}

impl LifecycleCommand {
    fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(59);
        bytes.extend_from_slice(COMMAND_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.push(self.kind.tag());
        bytes.extend_from_slice(&self.now_ms.to_be_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.operation_id);
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() != 59 || bytes.get(..8) != Some(COMMAND_MAGIC.as_slice()) {
            return Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "command has an invalid size or magic",
            ));
        }
        let version = read_u16(bytes, 8, "command version")?;
        if version != 1 {
            return Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "unsupported command version",
            ));
        }
        let request_id = read_array::<16>(bytes, 10, "command request ID")?;
        if request_id.iter().all(|byte| *byte == 0) {
            return Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "command request ID is zero",
            ));
        }
        let tag = *bytes
            .get(26)
            .ok_or_else(|| err("LIFECYCLE_COMMAND_MALFORMED", "command tag is missing"))?;
        let command = Self {
            request_id,
            kind: CommandKind::from_tag(tag)?,
            now_ms: read_u64(bytes, 27, "command time")?,
            epoch: read_u64(bytes, 35, "command epoch")?,
            operation_id: read_array::<16>(bytes, 43, "command operation ID")?,
        };
        command.validate_canonical()?;
        Ok(command)
    }

    fn validate_canonical(self) -> Result<(), ClusterError> {
        match self.kind {
            CommandKind::Promote if self.epoch > 0 && self.operation_id == [0; 16] => Ok(()),
            CommandKind::Emit if self.epoch > 0 && self.operation_id != [0; 16] => Ok(()),
            CommandKind::Status
            | CommandKind::Tick
            | CommandKind::Close
            | CommandKind::Stop
            | CommandKind::Replay
                if self.epoch == 0 && self.operation_id == [0; 16] =>
            {
                Ok(())
            }
            _ => Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "unused command fields are not canonical",
            )),
        }
    }
}

#[derive(Clone, Debug)]
struct SignedLifecycleCommand {
    command: LifecycleCommand,
    target_node: LifecycleNodeId,
    signature: [u8; 64],
}

impl SignedLifecycleCommand {
    fn sign(
        command: LifecycleCommand,
        target_node: LifecycleNodeId,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut signed = Self {
            command,
            target_node,
            signature: [0; 64],
        };
        signed.signature = key
            .sign(&domain_preimage(COMMAND_DOMAIN, &signed.unsigned_bytes()?))
            .to_bytes();
        Ok(signed)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() != COMMAND_LEN {
            return Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "signed command has an invalid size",
            ));
        }
        let target_node = match read_u8(bytes, 59, "command target node")? {
            1 => LifecycleNodeId::NodeA,
            2 => LifecycleNodeId::NodeB,
            _ => {
                return Err(err(
                    "LIFECYCLE_COMMAND_MALFORMED",
                    "unknown command target node",
                ));
            }
        };
        Ok(Self {
            command: LifecycleCommand::from_bytes(bytes.get(..59).ok_or_else(|| {
                err("LIFECYCLE_COMMAND_MALFORMED", "command payload is missing")
            })?)?,
            target_node,
            signature: read_array::<64>(bytes, COMMAND_UNSIGNED_LEN, "command signature")?,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    fn verify(
        &self,
        expected_node: LifecycleNodeId,
        key: &VerifyingKey,
    ) -> Result<(), ClusterError> {
        if self.target_node != expected_node {
            return Err(err(
                "LIFECYCLE_COMMAND_BINDING_REFUSED",
                "command target does not match this node",
            ));
        }
        key.verify_strict(
            &domain_preimage(COMMAND_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "LIFECYCLE_COMMAND_AUTH_REFUSED",
                "invalid lifecycle controller signature",
            )
        })
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.command.validate_canonical()?;
        let mut bytes = self.command.to_bytes();
        bytes.push(self.target_node.tag());
        if bytes.len() != COMMAND_UNSIGNED_LEN {
            return Err(err(
                "LIFECYCLE_COMMAND_MALFORMED",
                "internal signed command length mismatch",
            ));
        }
        Ok(bytes)
    }
}

struct SignedLifecycleResponse {
    request_id: [u8; 16],
    report: LifecycleReport,
    signature: [u8; 64],
}

impl SignedLifecycleResponse {
    fn sign(
        request_id: [u8; 16],
        report: LifecycleReport,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut response = Self {
            request_id,
            report,
            signature: [0; 64],
        };
        let unsigned = response.unsigned_bytes()?;
        response.signature = key
            .sign(&domain_preimage(RESPONSE_DOMAIN, &unsigned))
            .to_bytes();
        Ok(response)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() != RESPONSE_LEN || bytes.get(..8) != Some(RESPONSE_MAGIC.as_slice()) {
            return Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "response has an invalid size or magic",
            ));
        }
        if read_u16(bytes, 8, "response version")? != 1 {
            return Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "unsupported response version",
            ));
        }
        let response = Self {
            request_id: read_array::<16>(bytes, 10, "response request ID")?,
            report: LifecycleReport {
                node_id: LifecycleNodeId::from_tag(read_u8(bytes, 26, "response node")?)?,
                reason_code: LifecycleReasonCode::from_tag(read_u16(
                    bytes,
                    27,
                    "response reason",
                )?)?,
                state: LifecycleState::from_tag(read_u8(bytes, 29, "response state")?)?,
                highest_epoch: read_u64(bytes, 30, "response epoch")?,
                incarnation: read_u64(bytes, 38, "response incarnation")?,
                store_generation: read_u64(bytes, 46, "response generation")?,
                effect_count: read_u64(bytes, 54, "response effect count")?,
                commit_index: read_u64(bytes, 62, "response commit")?,
                state_root: read_array::<32>(bytes, 70, "response state root")?,
                lease_expires_at_ms: read_u64(bytes, 102, "response lease expiry")?,
            },
            signature: read_array::<64>(bytes, RESPONSE_UNSIGNED_LEN, "response signature")?,
        };
        Ok(response)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    fn verify(
        &self,
        expected_request_id: &[u8; 16],
        expected_node: LifecycleNodeId,
        key: &VerifyingKey,
    ) -> Result<(), ClusterError> {
        if &self.request_id != expected_request_id || self.report.node_id != expected_node {
            return Err(err(
                "LIFECYCLE_RESPONSE_BINDING_REFUSED",
                "response does not bind the request and expected node",
            ));
        }
        key.verify_strict(
            &domain_preimage(RESPONSE_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "LIFECYCLE_RESPONSE_AUTH_REFUSED",
                "invalid node response signature",
            )
        })
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        if self.request_id.iter().all(|byte| *byte == 0) {
            return Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "response request ID is zero",
            ));
        }
        let mut bytes = Vec::with_capacity(RESPONSE_UNSIGNED_LEN);
        bytes.extend_from_slice(RESPONSE_MAGIC);
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&self.request_id);
        bytes.push(self.report.node_id.tag());
        bytes.extend_from_slice(&self.report.reason_code.tag().to_be_bytes());
        bytes.push(self.report.state.tag());
        bytes.extend_from_slice(&self.report.highest_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.report.incarnation.to_be_bytes());
        bytes.extend_from_slice(&self.report.store_generation.to_be_bytes());
        bytes.extend_from_slice(&self.report.effect_count.to_be_bytes());
        bytes.extend_from_slice(&self.report.commit_index.to_be_bytes());
        bytes.extend_from_slice(&self.report.state_root);
        bytes.extend_from_slice(&self.report.lease_expires_at_ms.to_be_bytes());
        if bytes.len() != RESPONSE_UNSIGNED_LEN {
            return Err(err(
                "LIFECYCLE_RESPONSE_MALFORMED",
                "internal response length mismatch",
            ));
        }
        Ok(bytes)
    }
}

/// Loopback-only client that authenticates every lifecycle node response.
pub struct LifecycleClient {
    address: SocketAddr,
    node_id: LifecycleNodeId,
    public_key: VerifyingKey,
    controller_signing_key: SigningKey,
    timeout: Duration,
    next_request: u64,
    last_command: Option<SignedLifecycleCommand>,
}

impl LifecycleClient {
    #[must_use]
    pub fn new(
        address: SocketAddr,
        node_id: LifecycleNodeId,
        public_key: VerifyingKey,
        controller_signing_key: SigningKey,
        timeout: Duration,
    ) -> Self {
        Self {
            address,
            node_id,
            public_key,
            controller_signing_key,
            timeout,
            next_request: 1,
            last_command: None,
        }
    }

    pub fn status(&mut self, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Status, now_ms, 0, [0; 16])
    }

    pub fn promote(&mut self, epoch: u64, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Promote, now_ms, epoch, [0; 16])
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Tick, now_ms, 0, [0; 16])
    }

    pub fn emit(
        &mut self,
        epoch: u64,
        now_ms: u64,
        operation_id: [u8; 16],
    ) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Emit, now_ms, epoch, operation_id)
    }

    pub fn close(&mut self, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Close, now_ms, 0, [0; 16])
    }

    pub fn stop(&mut self, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Stop, now_ms, 0, [0; 16])
    }

    pub fn replay_last_proof(&mut self, now_ms: u64) -> Result<LifecycleReport, ClusterError> {
        self.send(CommandKind::Replay, now_ms, 0, [0; 16])
    }

    /// Retries the exact previous signed controller request without changing
    /// its request ID. The node returns its cached decision without reapplying
    /// the operation.
    pub fn retry_last_command(&mut self) -> Result<LifecycleReport, ClusterError> {
        let signed = self.last_command.clone().ok_or_else(|| {
            err(
                "LIFECYCLE_COMMAND_RETRY_REFUSED",
                "no prior signed controller command is available",
            )
        })?;
        self.exchange(&signed)
    }

    fn send(
        &mut self,
        kind: CommandKind,
        now_ms: u64,
        epoch: u64,
        operation_id: [u8; 16],
    ) -> Result<LifecycleReport, ClusterError> {
        let request_id = request_id(self.next_request);
        self.next_request = self
            .next_request
            .checked_add(1)
            .ok_or_else(|| err("LIFECYCLE_REQUEST_EXHAUSTED", "request counter overflow"))?;
        let command = LifecycleCommand {
            request_id,
            kind,
            now_ms,
            epoch,
            operation_id,
        };
        command.validate_canonical()?;
        let signed =
            SignedLifecycleCommand::sign(command, self.node_id, &self.controller_signing_key)?;
        self.last_command = Some(signed.clone());
        self.exchange(&signed)
    }

    fn exchange(&self, signed: &SignedLifecycleCommand) -> Result<LifecycleReport, ClusterError> {
        ensure_loopback(self.address)?;
        if self.timeout.is_zero() {
            return Err(err("TIMEOUT_REFUSED", "lifecycle client timeout is zero"));
        }
        let mut stream =
            TcpStream::connect_timeout(&self.address, self.timeout).map_err(|error| {
                err(
                    "LIFECYCLE_NODE_UNAVAILABLE",
                    format!("{}: {error}", self.address),
                )
            })?;
        configure_stream(&stream, self.timeout)?;
        let codec = FrameCodec::new(MAX_LIFECYCLE_FRAME)
            .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
        codec
            .write_frame(&mut stream, &signed.to_bytes()?)
            .map_err(|error| err("LIFECYCLE_COMMAND_WRITE_FAILED", error.to_string()))?;
        let bytes = codec
            .read_frame(&mut stream)
            .map_err(|error| err("LIFECYCLE_RESPONSE_READ_FAILED", error.to_string()))?
            .ok_or_else(|| {
                err(
                    "LIFECYCLE_RESPONSE_MISSING",
                    "node closed without a response",
                )
            })?;
        let response = SignedLifecycleResponse::from_bytes(&bytes)?;
        response.verify(&signed.command.request_id, self.node_id, &self.public_key)?;
        Ok(response.report)
    }
}

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

type LifecycleBackend = FaultInjectingBackend<FileBackend>;

struct LifecycleNodeRuntime {
    node_id: LifecycleNodeId,
    signing_key: SigningKey,
    witness_key: VerifyingKey,
    controller_key: VerifyingKey,
    witness_address: SocketAddr,
    io_timeout: Duration,
    policy_hash: [u8; 32],
    store: DurableAuthorityStore<LifecycleBackend>,
    progress_commit: u64,
    progress_root: [u8; 32],
    clock: ManualClock,
    effects: TestEffectActor<ManualClock>,
    state: LifecycleState,
    active_epoch: Option<u64>,
    lease_expires_at_ms: u64,
    last_now_ms: u64,
    terminal_fault: bool,
    last_envelope: Option<SignedPromotionEnvelope>,
    last_controller_counter: u64,
    last_controller_command: Option<LifecycleCommand>,
    last_controller_report: Option<LifecycleReport>,
}

impl LifecycleNodeRuntime {
    fn open(config: &LifecycleNodeConfig) -> Result<Self, ClusterError> {
        let signing_key = load_private_seed(&config.signing_key_file)?;
        let witness_key = load_public_key(&config.witness_public_key_file)?;
        let controller_key = load_public_key(&config.controller_public_key_file)?;
        require_distinct_role_keys(&[
            (config.node_id.as_str(), &signing_key.verifying_key()),
            (LIFECYCLE_WITNESS, &witness_key),
            ("lifecycle-controller", &controller_key),
        ])?;
        let wal_bytes = fs::read(&config.wal_path)
            .map_err(|error| err("LIFECYCLE_WAL_READ_REFUSED", error.to_string()))?;
        let recovered = recover_wal(&wal_bytes)
            .map_err(|error| err("LIFECYCLE_WAL_RECOVERY_REFUSED", error.to_string()))?;
        let rules = lifecycle_fault_rules(config.store_fault);
        let backend = FaultInjectingBackend::new(FileBackend, rules);
        let mut store = DurableAuthorityStore::open_in(
            &config.store_directory,
            lifecycle_node_store_identity(config.node_id)?,
            backend,
        )
        .map_err(|error| err("LIFECYCLE_STORE_OPEN_REFUSED", error.to_string()))?;
        let incarnation = store.state().incarnation().checked_add(1).ok_or_else(|| {
            err(
                "LIFECYCLE_INCARNATION_EXHAUSTED",
                "durable incarnation cannot advance",
            )
        })?;
        store
            .allocate_incarnation(incarnation)
            .map_err(|error| err("LIFECYCLE_INCARNATION_REFUSED", error.to_string()))?;
        store
            .record_progress(
                recovered.commit_index,
                StoreStateRoot::new(recovered.state_root),
            )
            .map_err(|error| err("LIFECYCLE_PROGRESS_REFUSED", error.to_string()))?;
        let accepted_epoch = store.state().highest_epoch();
        let clock = ManualClock::new(0);
        let gate = EffectGate::recover(
            core_node(config.node_id.as_str())?,
            core_workload()?,
            PolicyHash::new(config.policy_hash),
            GateRecoveryState::new(Epoch(accepted_epoch), Incarnation(incarnation), 0),
            clock.clone(),
        );
        Ok(Self {
            node_id: config.node_id,
            signing_key,
            witness_key,
            controller_key,
            witness_address: config.witness_address,
            io_timeout: config.io_timeout,
            policy_hash: config.policy_hash,
            store,
            progress_commit: recovered.commit_index,
            progress_root: recovered.state_root,
            clock,
            effects: TestEffectActor::new(gate),
            state: LifecycleState::Standby,
            active_epoch: None,
            lease_expires_at_ms: 0,
            last_now_ms: 0,
            terminal_fault: false,
            last_envelope: None,
            last_controller_counter: 0,
            last_controller_command: None,
            last_controller_report: None,
        })
    }

    fn apply_controller_command(
        &mut self,
        command: LifecycleCommand,
    ) -> Result<(LifecycleReport, bool, bool), ClusterError> {
        let counter = controller_request_counter(&command.request_id)?;
        if counter < self.last_controller_counter {
            return Err(err(
                "LIFECYCLE_COMMAND_REPLAY_REFUSED",
                "controller request ID is older than the latest accepted request",
            ));
        }
        if counter == self.last_controller_counter {
            if self.last_controller_command != Some(command) {
                return Err(err(
                    "LIFECYCLE_COMMAND_REPLAY_REFUSED",
                    "controller request ID was reused with different content",
                ));
            }
            let report = self.last_controller_report.clone().ok_or_else(|| {
                err(
                    "LIFECYCLE_COMMAND_REPLAY_REFUSED",
                    "cached controller decision is unavailable",
                )
            })?;
            return Ok((report, false, true));
        }

        let (reason, stop) = self.handle(command);
        let report = self.report(reason);
        self.last_controller_counter = counter;
        self.last_controller_command = Some(command);
        self.last_controller_report = Some(report.clone());
        Ok((report, stop, false))
    }

    fn handle(&mut self, command: LifecycleCommand) -> (LifecycleReasonCode, bool) {
        let time_result = self.apply_time(command.now_ms);
        if let Err(code) = time_result {
            return (code, false);
        }
        let result = match command.kind {
            CommandKind::Status => LifecycleReasonCode::Status,
            CommandKind::Promote => self.promote(command.epoch, command.now_ms),
            CommandKind::Tick => LifecycleReasonCode::TickApplied,
            CommandKind::Emit => self.emit(command.epoch, command.operation_id),
            CommandKind::Close => self.close(),
            CommandKind::Stop => {
                let _ = self.close();
                LifecycleReasonCode::Stopping
            }
            CommandKind::Replay => self.replay(command.now_ms),
        };
        (result, command.kind == CommandKind::Stop)
    }

    fn apply_time(&mut self, now_ms: u64) -> Result<(), LifecycleReasonCode> {
        self.clock.set(now_ms);
        if now_ms < self.last_now_ms {
            let _ = self.effects.tick();
            self.state = LifecycleState::SelfFenced;
            self.terminal_fault = true;
            return Err(LifecycleReasonCode::RefusedClockRollback);
        }
        self.last_now_ms = now_ms;
        match self.effects.tick() {
            Ok(true) => {
                self.state = LifecycleState::SelfFenced;
                self.active_epoch = None;
                self.lease_expires_at_ms = 0;
            }
            Ok(false) => {}
            Err(_) => {
                self.state = LifecycleState::SelfFenced;
                self.terminal_fault = true;
                return Err(LifecycleReasonCode::RefusedClockRollback);
            }
        }
        Ok(())
    }

    fn promote(&mut self, epoch: u64, now_ms: u64) -> LifecycleReasonCode {
        if self.terminal_fault || self.store.is_poisoned() {
            return LifecycleReasonCode::RefusedTerminalFault;
        }
        if self.state == LifecycleState::Active {
            return LifecycleReasonCode::RefusedAlreadyActive;
        }
        let Ok((lease_start, lease_end)) = lease_for_epoch(epoch) else {
            return LifecycleReasonCode::RefusedEpoch;
        };
        if now_ms < lease_start || now_ms >= lease_end {
            return LifecycleReasonCode::RefusedLeaseNotActive;
        }
        if epoch < self.store.state().highest_epoch() {
            return LifecycleReasonCode::RefusedEpoch;
        }
        let Ok(expected_root) = expected_state_root() else {
            self.terminal_fault = true;
            self.state = LifecycleState::SelfFenced;
            return LifecycleReasonCode::RefusedTerminalFault;
        };
        if self.progress_commit < REQUIRED_COMMIT || self.progress_root != expected_root {
            return LifecycleReasonCode::RefusedCandidateLagging;
        }
        self.state = LifecycleState::Candidate;
        match self.perform_promotion(epoch, now_ms, lease_start, lease_end) {
            Ok(signed) => {
                self.last_envelope = Some(signed);
                self.active_epoch = Some(epoch);
                self.lease_expires_at_ms = lease_end;
                self.state = LifecycleState::Active;
                LifecycleReasonCode::Promoted
            }
            Err(refusal) => {
                if refusal.terminal {
                    self.terminal_fault = true;
                    self.state = LifecycleState::SelfFenced;
                } else {
                    self.state = LifecycleState::Standby;
                }
                eprintln!(
                    "event=lifecycle_promotion_refusal node={} code={} detail={}",
                    self.node_id.as_str(),
                    refusal.code.as_str(),
                    refusal.detail
                );
                refusal.code
            }
        }
    }

    fn perform_promotion(
        &mut self,
        epoch: u64,
        now_ms: u64,
        lease_start: u64,
        lease_end: u64,
    ) -> Result<SignedPromotionEnvelope, LifecycleRefusal> {
        if self.policy_hash != POLICY_HASH {
            return Err(LifecycleRefusal::new(
                LifecycleReasonCode::RefusedPolicy,
                false,
                "local policy hash differs from lifecycle capsule",
            ));
        }
        let provisional = provisional_envelope(
            self.node_id,
            self.store.state().incarnation(),
            epoch,
            now_ms,
            lease_start,
            lease_end,
            self.progress_commit,
            self.progress_root,
            self.policy_hash,
            &self.signing_key,
        )
        .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let proposal_digest = provisional
            .envelope()
            .quorum_certificate
            .binding
            .proposal_digest()
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        self.store
            .record_vote(
                VoteRecord::new(epoch, self.node_id.as_str(), proposal_digest)
                    .map_err(|error| LifecycleRefusal::durability(error.to_string()))?,
            )
            .map_err(|error| LifecycleRefusal::durability(error.to_string()))?;
        let response = request_lifecycle_witness(
            self.witness_address,
            self.io_timeout,
            &provisional,
            &self.witness_key,
        )?;
        if !response.decision().is_granted() {
            return Err(LifecycleRefusal::new(
                LifecycleReasonCode::RefusedWitnessVote,
                false,
                "Witness refused the durable vote",
            ));
        }
        let final_envelope = PromotionEnvelope::from_canonical_bytes(response.envelope_bytes())
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        exact_final_scope(
            &final_envelope,
            self.node_id,
            self.store.state().incarnation(),
            epoch,
            self.progress_commit,
            self.progress_root,
            self.policy_hash,
        )
        .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let signed = SignedPromotionEnvelope::sign(
            final_envelope,
            canonical_id(LIFECYCLE_KEY_ID)
                .map_err(|error| LifecycleRefusal::proof(error.to_string()))?,
            &self.signing_key,
        )
        .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let resolver = NodeResolver {
            node_id: self.node_id,
            node_key: self.signing_key.verifying_key(),
            witness_key: self.witness_key,
        };
        signed
            .verify(&resolver)
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let current = current_authority(epoch, signed.envelope())
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let proof = to_core_proof(signed.envelope())
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let policy = core_policy(self.policy_hash)
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let validated = validate_promotion(&proof, &current, &policy, now_ms)
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let signed_digest = signed
            .digest()
            .map_err(|error| LifecycleRefusal::proof(error.to_string()))?;
        let lease = LeaseBounds::new(lease_start, lease_end)
            .map_err(|error| LifecycleRefusal::durability(error.to_string()))?;
        self.store
            .record_promotion(
                PromotionRecord::new(
                    epoch,
                    proposal_digest,
                    signed_digest,
                    lease,
                    self.progress_commit,
                    StoreStateRoot::new(self.progress_root),
                )
                .map_err(|error| LifecycleRefusal::durability(error.to_string()))?,
            )
            .map_err(|error| LifecycleRefusal::durability(error.to_string()))?;
        let persistence = self
            .effects
            .stage(validated)
            .map_err(|error| LifecycleRefusal::gate(error.to_string()))?;
        self.store
            .record_activation(
                ActivationReceipt::new(
                    epoch,
                    self.node_id.as_str(),
                    self.store.state().incarnation(),
                    signed_digest,
                    now_ms,
                    lease_end,
                )
                .map_err(|error| LifecycleRefusal::durability(error.to_string()))?,
            )
            .map_err(|error| LifecycleRefusal::durability(error.to_string()))?;
        self.effects
            .confirm_persisted(&persistence)
            .map_err(|error| LifecycleRefusal::gate(error.to_string()))?;
        let receipt = self
            .effects
            .activate()
            .map_err(|error| LifecycleRefusal::gate(error.to_string()))?;
        if receipt.holder.as_str() != self.node_id.as_str()
            || receipt.epoch.0 != epoch
            || receipt.incarnation.0 != self.store.state().incarnation()
            || receipt.expires_at_ms != lease_end
            || receipt.durable_commit.0 != self.progress_commit
            || receipt.state_root.as_bytes() != &self.progress_root
        {
            self.effects.close();
            return Err(LifecycleRefusal::new(
                LifecycleReasonCode::RefusedGate,
                true,
                "activation receipt differs from durable promotion scope",
            ));
        }
        Ok(signed)
    }

    fn emit(&mut self, epoch: u64, operation_id: [u8; 16]) -> LifecycleReasonCode {
        if self.state != LifecycleState::Active || self.active_epoch != Some(epoch) {
            return LifecycleReasonCode::RefusedNotActive;
        }
        match self.effects.emit(
            operation_id,
            match core_node(self.node_id.as_str()) {
                Ok(node) => node,
                Err(_) => {
                    self.state = LifecycleState::SelfFenced;
                    self.terminal_fault = true;
                    return LifecycleReasonCode::RefusedTerminalFault;
                }
            },
            Epoch(epoch),
            b"LIFECYCLE_TEST_EFFECT",
        ) {
            Ok(EffectOutcome::Recorded) => LifecycleReasonCode::EffectRecorded,
            Ok(EffectOutcome::AlreadyRecorded) => LifecycleReasonCode::EffectAlreadyRecorded,
            Err(_) => {
                self.state = LifecycleState::SelfFenced;
                self.active_epoch = None;
                self.lease_expires_at_ms = 0;
                LifecycleReasonCode::RefusedGate
            }
        }
    }

    fn close(&mut self) -> LifecycleReasonCode {
        self.state = LifecycleState::Draining;
        self.effects.close();
        self.active_epoch = None;
        self.lease_expires_at_ms = 0;
        self.state = LifecycleState::SelfFenced;
        LifecycleReasonCode::Closed
    }

    fn replay(&mut self, now_ms: u64) -> LifecycleReasonCode {
        let Some(signed) = self.last_envelope.as_ref() else {
            return LifecycleReasonCode::RefusedReplay;
        };
        let Ok(proof) = to_core_proof(signed.envelope()) else {
            self.state = LifecycleState::SelfFenced;
            self.terminal_fault = true;
            return LifecycleReasonCode::RefusedTerminalFault;
        };
        let current = CoreAuthorityState {
            epoch: Epoch(self.store.state().highest_epoch()),
            holder: core_node(self.node_id.as_str()).ok(),
            lease_expires_at_ms: self
                .store
                .state()
                .last_promotion()
                .map(|promotion| promotion.lease().expires_at_ms()),
        };
        let Ok(policy) = core_policy(self.policy_hash) else {
            return LifecycleReasonCode::RefusedReplay;
        };
        if validate_promotion(&proof, &current, &policy, now_ms).is_err() {
            LifecycleReasonCode::RefusedReplay
        } else {
            self.effects.close();
            self.state = LifecycleState::SelfFenced;
            self.terminal_fault = true;
            LifecycleReasonCode::RefusedTerminalFault
        }
    }

    fn report(&self, reason_code: LifecycleReasonCode) -> LifecycleReport {
        LifecycleReport {
            node_id: self.node_id,
            reason_code,
            state: self.state,
            highest_epoch: self.store.state().highest_epoch(),
            incarnation: self.store.state().incarnation(),
            store_generation: self.store.generation(),
            effect_count: u64::try_from(self.effects.records().len()).unwrap_or(u64::MAX),
            commit_index: self.progress_commit,
            state_root: self.progress_root,
            lease_expires_at_ms: self.lease_expires_at_ms,
        }
    }
}

struct LifecycleRefusal {
    code: LifecycleReasonCode,
    terminal: bool,
    detail: String,
}

impl LifecycleRefusal {
    fn new(code: LifecycleReasonCode, terminal: bool, detail: impl Into<String>) -> Self {
        Self {
            code,
            terminal,
            detail: detail.into(),
        }
    }

    fn durability(detail: impl Into<String>) -> Self {
        Self::new(LifecycleReasonCode::RefusedDurability, true, detail)
    }

    fn proof(detail: impl Into<String>) -> Self {
        Self::new(LifecycleReasonCode::RefusedProof, true, detail)
    }

    fn gate(detail: impl Into<String>) -> Self {
        Self::new(LifecycleReasonCode::RefusedGate, true, detail)
    }
}

/// Runs one long-lived Node A or Node B lifecycle service.
pub fn serve_lifecycle_node(config: LifecycleNodeConfig) -> Result<(), ClusterError> {
    ensure_loopback(config.listen)?;
    ensure_loopback(config.witness_address)?;
    ensure_service_bounds(config.max_connections, config.io_timeout)?;
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.witness_public_key_file.as_path(),
            config.controller_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        Some(&config.wal_path),
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.witness_public_key_file.as_path(),
            config.controller_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        Some(&config.wal_path),
    )?;
    require_disjoint_store_and_file(&config.store_directory, &config.wal_path)?;
    prepare_store_directory(&config.store_directory)?;
    prepare_file_parent(&config.wal_path)?;
    let _store_lock = OwnerLock::for_store(&config.store_directory, config.node_id.as_str())?;
    let _wal_lock = OwnerLock::for_file(&config.wal_path, config.node_id.as_str())?;
    let mut runtime = LifecycleNodeRuntime::open(&config)?;
    let listener = TcpListener::bind(config.listen).map_err(|error| {
        err(
            "LIFECYCLE_NODE_BIND_FAILED",
            format!("{}: {error}", config.listen),
        )
    })?;
    let local = listener
        .local_addr()
        .map_err(|error| err("LIFECYCLE_NODE_BIND_FAILED", error.to_string()))?;
    ensure_loopback(local)?;
    let codec = FrameCodec::new(MAX_LIFECYCLE_FRAME)
        .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
    write_ready_file(&config.ready_file, &local.to_string())?;
    eprintln!(
        "event=lifecycle_ready node={} state={}",
        config.node_id.as_str(),
        LifecycleState::Standby.as_str()
    );

    for _ in 0..config.max_connections {
        let (mut stream, remote) = accept(&listener, "LIFECYCLE_NODE_ACCEPT_FAILED")?;
        if !remote.ip().is_loopback() {
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        let result = handle_lifecycle_node_connection(&mut stream, codec, &mut runtime);
        match result {
            Ok(stop) if stop => return Ok(()),
            Ok(false) => {}
            Err(error) => eprintln!("event=lifecycle_command_refusal {error}"),
            Ok(true) => return Ok(()),
        }
    }
    runtime.close();
    Ok(())
}

fn handle_lifecycle_node_connection(
    stream: &mut TcpStream,
    codec: FrameCodec,
    runtime: &mut LifecycleNodeRuntime,
) -> Result<bool, ClusterError> {
    let payload = codec
        .read_frame(stream)
        .map_err(|error| err("LIFECYCLE_COMMAND_READ_FAILED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "LIFECYCLE_COMMAND_MISSING",
                "connection closed without command",
            )
        })?;
    let signed = SignedLifecycleCommand::from_bytes(&payload)?;
    signed.verify(runtime.node_id, &runtime.controller_key)?;
    let command = signed.command;
    let (report, stop, duplicate) = runtime.apply_controller_command(command)?;
    let response =
        SignedLifecycleResponse::sign(command.request_id, report.clone(), &runtime.signing_key)?;
    codec
        .write_frame(stream, &response.to_bytes()?)
        .map_err(|error| err("LIFECYCLE_RESPONSE_WRITE_FAILED", error.to_string()))?;
    eprintln!(
        "event=lifecycle_decision node={} code={} state={} epoch={} generation={} effects={} duplicate={duplicate}",
        report.node_id.as_str(),
        report.reason_code.as_str(),
        report.state.as_str(),
        report.highest_epoch,
        report.store_generation,
        report.effect_count
    );
    Ok(stop)
}

struct LifecycleWitnessResolver {
    node_a_key: VerifyingKey,
    node_b_key: VerifyingKey,
}

impl VerificationKeyResolver for LifecycleWitnessResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if key_id.as_str() != LIFECYCLE_KEY_ID {
            return None;
        }
        match principal.as_str() {
            NODE_A => Some(self.node_a_key),
            NODE_B => Some(self.node_b_key),
            _ => None,
        }
    }
}

/// Runs the independent durable Witness for the bounded lifecycle laboratory.
pub fn serve_lifecycle_witness(config: LifecycleWitnessConfig) -> Result<(), ClusterError> {
    ensure_loopback(config.listen)?;
    ensure_service_bounds(config.max_connections, config.io_timeout)?;
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.node_a_public_key_file.as_path(),
            config.node_b_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        None,
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.node_a_public_key_file.as_path(),
            config.node_b_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        None,
    )?;
    let witness_signing_key = load_private_seed(&config.signing_key_file)?;
    let node_a_key = load_public_key(&config.node_a_public_key_file)?;
    let node_b_key = load_public_key(&config.node_b_public_key_file)?;
    let witness_key = witness_signing_key.verifying_key();
    require_distinct_role_keys(&[
        (LIFECYCLE_WITNESS, &witness_key),
        (NODE_A, &node_a_key),
        (NODE_B, &node_b_key),
    ])?;
    prepare_store_directory(&config.store_directory)?;
    let _store_lock = OwnerLock::for_store(&config.store_directory, LIFECYCLE_WITNESS)?;
    let policy = WitnessPolicy::new(
        canonical_id(LIFECYCLE_WITNESS)?,
        canonical_id(LIFECYCLE_KEY_ID)?,
        canonical_id(LIFECYCLE_WORKLOAD)?,
        config.policy_hash,
        [canonical_id(NODE_A)?, canonical_id(NODE_B)?],
        LEASE_DURATION_MS,
    )
    .map_err(|error| err("LIFECYCLE_WITNESS_POLICY_INVALID", error.to_string()))?;
    let mut actor = WitnessVoteActor::open(
        policy,
        SigningKey::from_bytes(witness_signing_key.as_bytes()),
        &config.store_directory,
        lifecycle_witness_store_identity()?,
        FileBackend,
    )
    .map_err(|error| err("LIFECYCLE_WITNESS_STORE_REFUSED", error.to_string()))?;
    let listener = TcpListener::bind(config.listen).map_err(|error| {
        err(
            "LIFECYCLE_WITNESS_BIND_FAILED",
            format!("{}: {error}", config.listen),
        )
    })?;
    let local = listener
        .local_addr()
        .map_err(|error| err("LIFECYCLE_WITNESS_BIND_FAILED", error.to_string()))?;
    ensure_loopback(local)?;
    let codec = FrameCodec::new(MAX_CLUSTER_FRAME)
        .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
    write_ready_file(&config.ready_file, &local.to_string())?;
    let resolver = LifecycleWitnessResolver {
        node_a_key,
        node_b_key,
    };

    for _ in 0..config.max_connections {
        let (mut stream, remote) = accept(&listener, "LIFECYCLE_WITNESS_ACCEPT_FAILED")?;
        if !remote.ip().is_loopback() {
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        if let Err(error) = handle_lifecycle_witness_connection(
            &mut stream,
            codec,
            &resolver,
            &witness_signing_key,
            &mut actor,
            config.policy_hash,
        ) {
            eprintln!("event=lifecycle_witness_refusal {error}");
        }
    }
    Ok(())
}

fn handle_lifecycle_witness_connection(
    stream: &mut TcpStream,
    codec: FrameCodec,
    resolver: &LifecycleWitnessResolver,
    witness_signing_key: &SigningKey,
    actor: &mut WitnessVoteActor<FileBackend>,
    policy_hash: [u8; 32],
) -> Result<(), ClusterError> {
    let payload = codec
        .read_frame(stream)
        .map_err(|error| err("LIFECYCLE_WITNESS_FRAME_REFUSED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "LIFECYCLE_WITNESS_REQUEST_MISSING",
                "connection closed without request",
            )
        })?;
    let request = SignedPromotionEnvelope::from_canonical_bytes(&payload)
        .map_err(|error| err("LIFECYCLE_WITNESS_REQUEST_MALFORMED", error.to_string()))?;
    request
        .verify(resolver)
        .map_err(|error| err("LIFECYCLE_WITNESS_REQUEST_AUTH_REFUSED", error.to_string()))?;
    let envelope = request.envelope();
    let request_digest = witness_request_digest(&payload)?;
    if let Err(scope_error) = lifecycle_witness_scope(envelope, actor, policy_hash) {
        let response = WitnessResponse::sign(
            envelope.message_id,
            request_digest,
            WitnessDecision::Refused,
            0,
            Vec::new(),
            witness_signing_key,
        )?;
        codec
            .write_frame(stream, &response.to_bytes()?)
            .map_err(|error| err("LIFECYCLE_WITNESS_FRAME_WRITE_FAILED", error.to_string()))?;
        eprintln!("event=lifecycle_witness_vote code=WITNESS_SCOPE_REFUSED detail={scope_error}");
        return Ok(());
    }

    let reply = actor.handle_vote(&envelope.quorum_certificate.binding);
    let (decision, generation, final_bytes) = if reply.is_granted() {
        let candidate_vote = envelope
            .quorum_certificate
            .votes()
            .first()
            .ok_or_else(|| err("LIFECYCLE_WITNESS_INTERNAL", "candidate vote missing"))?
            .clone();
        let witness_vote = reply
            .signed_vote()
            .ok_or_else(|| err("LIFECYCLE_WITNESS_INTERNAL", "durable vote missing"))?
            .clone();
        let certificate = QuorumCertificate::new(
            envelope.quorum_certificate.binding.clone(),
            2,
            vec![candidate_vote, witness_vote],
        )
        .map_err(|error| err("LIFECYCLE_WITNESS_CERTIFICATE_REFUSED", error.to_string()))?;
        let candidate = LifecycleNodeId::parse(envelope.candidate_node_id.as_str())?;
        let target = if envelope.epoch == 1 {
            None
        } else {
            Some(canonical_id(candidate.other().as_str())?)
        };
        let mechanism = if envelope.epoch == 1 {
            FenceMechanism::Bootstrap
        } else {
            FenceMechanism::EffectGateExpired
        };
        let (lease_start, _) = lease_for_epoch(envelope.epoch)?;
        let fence = FenceReceipt::sign(
            &certificate.binding,
            target,
            canonical_id(LIFECYCLE_WITNESS)?,
            canonical_id(LIFECYCLE_KEY_ID)?,
            mechanism,
            lease_start,
            fence_evidence_digest(envelope.epoch, candidate),
            witness_signing_key,
        )
        .map_err(|error| err("LIFECYCLE_WITNESS_FENCE_REFUSED", error.to_string()))?;
        let mut final_envelope = envelope.clone();
        final_envelope.quorum_certificate = certificate;
        final_envelope.fence_receipt = fence;
        final_envelope
            .validate()
            .map_err(|error| err("LIFECYCLE_WITNESS_ENVELOPE_REFUSED", error.to_string()))?;
        let bytes = final_envelope
            .to_canonical_bytes()
            .map_err(|error| err("LIFECYCLE_WITNESS_ENVELOPE_REFUSED", error.to_string()))?;
        let decision = match reply.code() {
            VoteReasonCode::GrantedDurablyRecorded => WitnessDecision::DurableGrant,
            VoteReasonCode::GrantedAlreadyDurable => WitnessDecision::DurableRetry,
            _ => {
                return Err(err(
                    "LIFECYCLE_WITNESS_INTERNAL",
                    "granted vote carried refusal code",
                ));
            }
        };
        let generation = reply
            .durable_generation()
            .ok_or_else(|| err("LIFECYCLE_WITNESS_INTERNAL", "generation missing"))?;
        (decision, generation, bytes)
    } else {
        (WitnessDecision::Refused, 0, Vec::new())
    };
    let response = WitnessResponse::sign(
        envelope.message_id,
        request_digest,
        decision,
        generation,
        final_bytes,
        witness_signing_key,
    )?;
    codec
        .write_frame(stream, &response.to_bytes()?)
        .map_err(|error| err("LIFECYCLE_WITNESS_FRAME_WRITE_FAILED", error.to_string()))?;
    eprintln!(
        "event=lifecycle_witness_vote code={decision:?} epoch={} candidate={} generation={generation}",
        envelope.epoch, envelope.candidate_node_id
    );
    Ok(())
}

fn lifecycle_witness_scope(
    envelope: &PromotionEnvelope,
    actor: &WitnessVoteActor<FileBackend>,
    policy_hash: [u8; 32],
) -> Result<(), ClusterError> {
    let candidate = LifecycleNodeId::parse(envelope.candidate_node_id.as_str())?;
    let durable_epoch = actor.highest_durable_epoch();
    if envelope.epoch < durable_epoch
        || envelope.epoch > durable_epoch.saturating_add(1)
        || (envelope.epoch == 1 && durable_epoch > 1)
    {
        return Err(err(
            "LIFECYCLE_WITNESS_EPOCH_REFUSED",
            "proposal is not the next epoch or an exact durable retry",
        ));
    }
    if envelope.epoch == durable_epoch {
        if actor.last_durable_candidate() != Some(candidate.as_str()) {
            return Err(err(
                "LIFECYCLE_WITNESS_DOUBLE_VOTE_REFUSED",
                "another candidate is already durable at this epoch",
            ));
        }
    } else if durable_epoch > 0
        && actor.last_durable_candidate() != Some(candidate.other().as_str())
    {
        return Err(err(
            "LIFECYCLE_WITNESS_TRANSFER_REFUSED",
            "next candidate does not differ from the durable prior holder",
        ));
    }
    let (lease_start, lease_end) = lease_for_epoch(envelope.epoch)?;
    let expected_root = expected_state_root()?;
    let votes = envelope.quorum_certificate.votes();
    let expected_target = if envelope.epoch == 1 {
        None
    } else {
        Some(candidate.other().as_str())
    };
    let actual_target = envelope.fence_receipt.target().map(CanonicalId::as_str);
    let expected_mechanism = if envelope.epoch == 1 {
        FenceMechanism::Bootstrap
    } else {
        FenceMechanism::EffectGateExpired
    };
    if envelope.workload_id.as_str() != LIFECYCLE_WORKLOAD
        || envelope.policy_hash != policy_hash
        || envelope.required_commit != REQUIRED_COMMIT
        || envelope.durable_commit < REQUIRED_COMMIT
        || envelope.state_root != expected_root
        || envelope.lease.not_before_ms != lease_start
        || envelope.lease.expires_at_ms != lease_end
        || envelope.quorum_certificate.threshold != 1
        || votes.len() != 1
        || votes
            .first()
            .is_none_or(|vote| vote.voter_id().as_str() != candidate.as_str())
        || envelope.fence_receipt.verifier_id().as_str() != candidate.as_str()
        || envelope.fence_receipt.key_id().as_str() != LIFECYCLE_KEY_ID
        || envelope.fence_receipt.mechanism() != expected_mechanism
        || actual_target != expected_target
    {
        return Err(err(
            "LIFECYCLE_WITNESS_SCOPE_REFUSED",
            "proposal differs from the pinned lifecycle policy, progress, lease, or fence",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn provisional_envelope(
    candidate: LifecycleNodeId,
    incarnation: u64,
    epoch: u64,
    now_ms: u64,
    lease_start: u64,
    lease_end: u64,
    durable_commit: u64,
    state_root: [u8; 32],
    policy_hash: [u8; 32],
    signing_key: &SigningKey,
) -> Result<SignedPromotionEnvelope, ClusterError> {
    let binding = QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: lifecycle_message_id(candidate, incarnation, epoch),
        workload_id: canonical_id(LIFECYCLE_WORKLOAD)?,
        candidate_node_id: canonical_id(candidate.as_str())?,
        candidate_incarnation: incarnation,
        epoch,
        policy_hash,
        required_commit: REQUIRED_COMMIT,
        durable_commit,
        state_root,
        lease_not_before_ms: lease_start,
        lease_expires_at_ms: lease_end,
    };
    let candidate_vote = SignedVote::sign(
        &binding,
        canonical_id(candidate.as_str())?,
        canonical_id(LIFECYCLE_KEY_ID)?,
        signing_key,
    )
    .map_err(|error| err("LIFECYCLE_CANDIDATE_VOTE_REFUSED", error.to_string()))?;
    let certificate = QuorumCertificate::new(binding.clone(), 1, vec![candidate_vote])
        .map_err(|error| err("LIFECYCLE_CERTIFICATE_REFUSED", error.to_string()))?;
    let (target, mechanism) = if epoch == 1 {
        (None, FenceMechanism::Bootstrap)
    } else {
        (
            Some(canonical_id(candidate.other().as_str())?),
            FenceMechanism::EffectGateExpired,
        )
    };
    let provisional_fence = FenceReceipt::sign(
        &binding,
        target,
        canonical_id(candidate.as_str())?,
        canonical_id(LIFECYCLE_KEY_ID)?,
        mechanism,
        now_ms,
        fence_evidence_digest(epoch, candidate),
        signing_key,
    )
    .map_err(|error| err("LIFECYCLE_PROVISIONAL_FENCE_REFUSED", error.to_string()))?;
    let envelope = PromotionEnvelope {
        protocol_version: PROTOCOL_VERSION,
        message_id: binding.message_id,
        workload_id: binding.workload_id.clone(),
        candidate_node_id: binding.candidate_node_id.clone(),
        candidate_incarnation: binding.candidate_incarnation,
        epoch: binding.epoch,
        policy_hash: binding.policy_hash,
        quorum_certificate: certificate,
        fence_receipt: provisional_fence,
        required_commit: binding.required_commit,
        durable_commit: binding.durable_commit,
        state_root: binding.state_root,
        health_attestation: HealthAttestation {
            node_id: binding.candidate_node_id.clone(),
            incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            healthy: true,
            passed_checks: 3,
            observed_at_ms: now_ms,
            attestation_digest: health_digest(candidate, incarnation, epoch),
        },
        lease: LeaseGrant {
            holder_node_id: binding.candidate_node_id,
            incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            not_before_ms: binding.lease_not_before_ms,
            expires_at_ms: binding.lease_expires_at_ms,
        },
    };
    SignedPromotionEnvelope::sign(envelope, canonical_id(LIFECYCLE_KEY_ID)?, signing_key)
        .map_err(|error| err("LIFECYCLE_PROVISIONAL_ENVELOPE_REFUSED", error.to_string()))
}

fn request_lifecycle_witness(
    address: SocketAddr,
    timeout: Duration,
    request: &SignedPromotionEnvelope,
    witness_key: &VerifyingKey,
) -> Result<WitnessResponse, LifecycleRefusal> {
    ensure_loopback(address).map_err(|error| {
        LifecycleRefusal::new(
            LifecycleReasonCode::RefusedWitnessUnavailable,
            false,
            error.to_string(),
        )
    })?;
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|error| {
        LifecycleRefusal::new(
            LifecycleReasonCode::RefusedWitnessUnavailable,
            false,
            error.to_string(),
        )
    })?;
    configure_stream(&stream, timeout).map_err(|error| {
        LifecycleRefusal::new(
            LifecycleReasonCode::RefusedWitnessUnavailable,
            false,
            error.to_string(),
        )
    })?;
    let codec = FrameCodec::new(MAX_CLUSTER_FRAME).map_err(|error| {
        LifecycleRefusal::new(
            LifecycleReasonCode::RefusedWitnessUnavailable,
            false,
            error.to_string(),
        )
    })?;
    let request_bytes = request.to_canonical_bytes().map_err(|error| {
        LifecycleRefusal::new(LifecycleReasonCode::RefusedProof, true, error.to_string())
    })?;
    codec
        .write_frame(&mut stream, &request_bytes)
        .map_err(|error| {
            LifecycleRefusal::new(
                LifecycleReasonCode::RefusedWitnessUnavailable,
                false,
                error.to_string(),
            )
        })?;
    let response_bytes = codec
        .read_frame(&mut stream)
        .map_err(|error| {
            LifecycleRefusal::new(
                LifecycleReasonCode::RefusedWitnessUnavailable,
                false,
                error.to_string(),
            )
        })?
        .ok_or_else(|| {
            LifecycleRefusal::new(
                LifecycleReasonCode::RefusedWitnessUnavailable,
                false,
                "Witness closed without response",
            )
        })?;
    let response = WitnessResponse::from_bytes(&response_bytes).map_err(|error| {
        LifecycleRefusal::new(
            LifecycleReasonCode::RefusedWitnessUnavailable,
            false,
            error.to_string(),
        )
    })?;
    let request_digest = witness_request_digest(&request_bytes).map_err(|error| {
        LifecycleRefusal::new(LifecycleReasonCode::RefusedProof, true, error.to_string())
    })?;
    response
        .verify(&request.envelope().message_id, &request_digest, witness_key)
        .map_err(|error| {
            LifecycleRefusal::new(
                LifecycleReasonCode::RefusedWitnessUnavailable,
                true,
                error.to_string(),
            )
        })?;
    Ok(response)
}

#[allow(clippy::too_many_arguments)]
fn exact_final_scope(
    envelope: &PromotionEnvelope,
    candidate: LifecycleNodeId,
    incarnation: u64,
    epoch: u64,
    commit_index: u64,
    state_root: [u8; 32],
    policy_hash: [u8; 32],
) -> Result<(), ClusterError> {
    let (lease_start, lease_end) = lease_for_epoch(epoch)?;
    let votes = envelope.quorum_certificate.votes();
    let expected_target = if epoch == 1 {
        None
    } else {
        Some(candidate.other().as_str())
    };
    if envelope.workload_id.as_str() != LIFECYCLE_WORKLOAD
        || envelope.candidate_node_id.as_str() != candidate.as_str()
        || envelope.candidate_incarnation != incarnation
        || envelope.epoch != epoch
        || envelope.policy_hash != policy_hash
        || envelope.required_commit != REQUIRED_COMMIT
        || envelope.durable_commit != commit_index
        || envelope.state_root != state_root
        || envelope.lease.not_before_ms != lease_start
        || envelope.lease.expires_at_ms != lease_end
        || envelope.quorum_certificate.threshold != 2
        || votes.len() != 2
        || votes
            .first()
            .is_none_or(|vote| vote.voter_id().as_str() != candidate.as_str())
        || votes
            .get(1)
            .is_none_or(|vote| vote.voter_id().as_str() != LIFECYCLE_WITNESS)
        || envelope.fence_receipt.verifier_id().as_str() != LIFECYCLE_WITNESS
        || envelope.fence_receipt.target().map(CanonicalId::as_str) != expected_target
    {
        return Err(err(
            "LIFECYCLE_FINAL_SCOPE_REFUSED",
            "final envelope differs from candidate request or pinned lifecycle scope",
        ));
    }
    Ok(())
}

struct NodeResolver {
    node_id: LifecycleNodeId,
    node_key: VerifyingKey,
    witness_key: VerifyingKey,
}

impl VerificationKeyResolver for NodeResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if key_id.as_str() != LIFECYCLE_KEY_ID {
            return None;
        }
        match principal.as_str() {
            value if value == self.node_id.as_str() => Some(self.node_key),
            LIFECYCLE_WITNESS => Some(self.witness_key),
            _ => None,
        }
    }
}

fn to_core_proof(envelope: &PromotionEnvelope) -> Result<CorePromotionProof, ClusterError> {
    let workload = core_workload()?;
    let candidate = core_node(envelope.candidate_node_id.as_str())?;
    let state_root = CoreStateRoot::new(envelope.state_root);
    let policy_hash = PolicyHash::new(envelope.policy_hash);
    let voters = envelope
        .quorum_certificate
        .votes()
        .iter()
        .map(|vote| core_node(vote.voter_id().as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let mechanism = match envelope.fence_receipt.mechanism() {
        FenceMechanism::Bootstrap => CoreFenceMechanism::Bootstrap,
        FenceMechanism::HardwarePower => CoreFenceMechanism::HardwarePower,
        FenceMechanism::StorageReservation => CoreFenceMechanism::StorageReservation,
        FenceMechanism::EffectGateExpired => CoreFenceMechanism::EffectGateExpired,
    };
    let target = envelope
        .fence_receipt
        .target()
        .map(|target| core_node(target.as_str()))
        .transpose()?;
    Ok(CorePromotionProof {
        workload: workload.clone(),
        candidate: candidate.clone(),
        candidate_incarnation: Incarnation(envelope.candidate_incarnation),
        epoch: Epoch(envelope.epoch),
        policy_hash,
        quorum: CoreQuorumCertificate {
            epoch: Epoch(envelope.epoch),
            workload: workload.clone(),
            candidate: candidate.clone(),
            candidate_incarnation: Incarnation(envelope.candidate_incarnation),
            policy_hash,
            required_commit: CommitIndex(envelope.required_commit),
            state_root,
            lease_not_before_ms: envelope.lease.not_before_ms,
            lease_expires_at_ms: envelope.lease.expires_at_ms,
            voters,
        },
        fence: CoreFenceReceipt {
            epoch: Epoch(envelope.epoch),
            target,
            verifier: core_node(envelope.fence_receipt.verifier_id().as_str())?,
            mechanism,
            observed_at_ms: envelope.fence_receipt.observed_at_ms(),
        },
        state: StateEvidence {
            required_commit: CommitIndex(envelope.required_commit),
            durable_commit: CommitIndex(envelope.durable_commit),
            state_root,
            observed_at_ms: envelope.health_attestation.observed_at_ms,
        },
        health: CoreHealthAttestation {
            workload: workload.clone(),
            node: candidate.clone(),
            incarnation: Incarnation(envelope.health_attestation.incarnation),
            epoch: Epoch(envelope.health_attestation.epoch),
            healthy: envelope.health_attestation.healthy,
            passed_checks: envelope.health_attestation.passed_checks,
            observed_at_ms: envelope.health_attestation.observed_at_ms,
        },
        lease: CoreLeaseGrant {
            workload,
            holder: candidate,
            incarnation: Incarnation(envelope.lease.incarnation),
            epoch: Epoch(envelope.lease.epoch),
            not_before_ms: envelope.lease.not_before_ms,
            expires_at_ms: envelope.lease.expires_at_ms,
        },
    })
}

fn current_authority(
    epoch: u64,
    envelope: &PromotionEnvelope,
) -> Result<CoreAuthorityState, ClusterError> {
    if epoch == 1 {
        return Ok(CoreAuthorityState::initial());
    }
    let previous_epoch = epoch
        .checked_sub(1)
        .ok_or_else(|| err("LIFECYCLE_EPOCH_REFUSED", "epoch underflow"))?;
    let (_, previous_expiry) = lease_for_epoch(previous_epoch)?;
    let holder = envelope
        .fence_receipt
        .target()
        .ok_or_else(|| {
            err(
                "LIFECYCLE_FENCE_REFUSED",
                "non-bootstrap promotion has no prior holder",
            )
        })?
        .as_str();
    Ok(CoreAuthorityState {
        epoch: Epoch(previous_epoch),
        holder: Some(core_node(holder)?),
        lease_expires_at_ms: Some(previous_expiry),
    })
}

fn core_policy(policy_hash: [u8; 32]) -> Result<SafetyPolicy, ClusterError> {
    SafetyPolicy::new(
        core_workload()?,
        PolicyHash::new(policy_hash),
        [core_node(NODE_A)?, core_node(NODE_B)?],
        [
            core_node(NODE_A)?,
            core_node(NODE_B)?,
            core_node(LIFECYCLE_WITNESS)?,
        ],
        2,
        Some(core_node(LIFECYCLE_WITNESS)?),
        3,
        100,
        LEASE_DURATION_MS,
        LEASE_GUARD_MS,
        true,
    )
    .map_err(|error| err("LIFECYCLE_POLICY_INVALID", error.to_string()))
}

fn lifecycle_fault_rules(fault: LifecycleStoreFault) -> Vec<FaultRule> {
    match fault {
        LifecycleStoreFault::None => Vec::new(),
        LifecycleStoreFault::PromotionWriteError => vec![FaultRule {
            operation: FaultOperation::Write,
            occurrence: 4,
            mode: FaultMode::Error(ErrorKind::Other),
        }],
        LifecycleStoreFault::PromotionPartialWrite => vec![FaultRule {
            operation: FaultOperation::Write,
            occurrence: 4,
            mode: FaultMode::PartialWrite {
                bytes: 31,
                error_kind: ErrorKind::Other,
            },
        }],
    }
}

fn lifecycle_node_store_identity(node: LifecycleNodeId) -> Result<StoreIdentity, ClusterError> {
    let store_id = match node {
        LifecycleNodeId::NodeA => [81; 16],
        LifecycleNodeId::NodeB => [82; 16],
    };
    StoreIdentity::new(
        LIFECYCLE_CLUSTER,
        LIFECYCLE_WORKLOAD,
        node.as_str(),
        StoreRole::DataNode,
        store_id,
    )
    .map_err(|error| err("LIFECYCLE_STORE_IDENTITY_INVALID", error.to_string()))
}

fn lifecycle_witness_store_identity() -> Result<StoreIdentity, ClusterError> {
    StoreIdentity::new(
        LIFECYCLE_CLUSTER,
        LIFECYCLE_WORKLOAD,
        LIFECYCLE_WITNESS,
        StoreRole::Witness,
        [83; 16],
    )
    .map_err(|error| err("LIFECYCLE_STORE_IDENTITY_INVALID", error.to_string()))
}

fn lease_for_epoch(epoch: u64) -> Result<(u64, u64), ClusterError> {
    let ordinal = epoch
        .checked_sub(1)
        .ok_or_else(|| err("LIFECYCLE_EPOCH_REFUSED", "epoch zero is invalid"))?;
    let offset = ordinal
        .checked_mul(LEASE_STRIDE_MS)
        .ok_or_else(|| err("LIFECYCLE_EPOCH_REFUSED", "lease schedule overflow"))?;
    let start = LEASE_BASE_MS
        .checked_add(offset)
        .ok_or_else(|| err("LIFECYCLE_EPOCH_REFUSED", "lease start overflow"))?;
    let end = start
        .checked_add(LEASE_DURATION_MS)
        .ok_or_else(|| err("LIFECYCLE_EPOCH_REFUSED", "lease expiry overflow"))?;
    Ok((start, end))
}

fn expected_state_root() -> Result<[u8; 32], ClusterError> {
    let bytes = expected_entry().encode();
    let recovered = recover_wal(&bytes)
        .map_err(|error| err("LIFECYCLE_EXPECTED_WAL_INVALID", error.to_string()))?;
    Ok(recovered.state_root)
}

fn expected_entry() -> WalEntry {
    WalEntry {
        commit_index: 1,
        operation_id: OperationId::new([9; 16]),
        previous_value: 0,
        increment: 1,
        value: 1,
    }
}

fn lifecycle_message_id(candidate: LifecycleNodeId, incarnation: u64, epoch: u64) -> MessageId {
    let mut digest = Sha256::new();
    digest.update(MESSAGE_ID_DOMAIN);
    digest.update(candidate.as_str().as_bytes());
    digest.update(incarnation.to_be_bytes());
    digest.update(epoch.to_be_bytes());
    let output: [u8; 32] = digest.finalize().into();
    let mut message_id = [0; 16];
    message_id.copy_from_slice(&output[..16]);
    MessageId::new(message_id)
}

fn fence_evidence_digest(epoch: u64, candidate: LifecycleNodeId) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(FENCE_EVIDENCE_DOMAIN);
    digest.update(epoch.to_be_bytes());
    digest.update(candidate.as_str().as_bytes());
    digest.finalize().into()
}

fn health_digest(candidate: LifecycleNodeId, incarnation: u64, epoch: u64) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"quorumarc/lifecycle/health/sha256/v1\0");
    digest.update(candidate.as_str().as_bytes());
    digest.update(incarnation.to_be_bytes());
    digest.update(epoch.to_be_bytes());
    digest.finalize().into()
}

fn request_id(counter: u64) -> [u8; 16] {
    let mut value = [0x51; 16];
    value[8..].copy_from_slice(&counter.to_be_bytes());
    value
}

fn controller_request_counter(request_id: &[u8; 16]) -> Result<u64, ClusterError> {
    if request_id[..8] != [0x51; 8] {
        return Err(err(
            "LIFECYCLE_COMMAND_MALFORMED",
            "controller request ID has an invalid domain prefix",
        ));
    }
    let mut counter_bytes = [0; 8];
    counter_bytes.copy_from_slice(&request_id[8..]);
    let counter = u64::from_be_bytes(counter_bytes);
    if counter == 0 {
        return Err(err(
            "LIFECYCLE_COMMAND_MALFORMED",
            "controller request counter is zero",
        ));
    }
    Ok(counter)
}

fn canonical_id(value: &str) -> Result<CanonicalId, ClusterError> {
    id(value)
}

fn core_node(value: &str) -> Result<NodeId, ClusterError> {
    NodeId::new(value).map_err(|error| err("LIFECYCLE_IDENTIFIER_INVALID", error.to_string()))
}

fn core_workload() -> Result<WorkloadId, ClusterError> {
    WorkloadId::new(LIFECYCLE_WORKLOAD)
        .map_err(|error| err("LIFECYCLE_IDENTIFIER_INVALID", error.to_string()))
}

fn ensure_loopback(address: SocketAddr) -> Result<(), ClusterError> {
    if !address.ip().is_loopback() {
        return Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost lifecycle lab"),
        ));
    }
    Ok(())
}

fn ensure_service_bounds(max_connections: u64, timeout: Duration) -> Result<(), ClusterError> {
    if max_connections == 0 {
        return Err(err("LIFECYCLE_CONFIG_REFUSED", "connection bound is zero"));
    }
    if timeout.is_zero() {
        return Err(err("TIMEOUT_REFUSED", "I/O timeout is zero"));
    }
    Ok(())
}

fn accept(
    listener: &TcpListener,
    code: &'static str,
) -> Result<(TcpStream, SocketAddr), ClusterError> {
    loop {
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(err(code, error.to_string())),
        }
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), ClusterError> {
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|error| err("SOCKET_CONFIG_FAILED", error.to_string()))
}

fn domain_preimage(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(domain.len().saturating_add(bytes.len()));
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(bytes);
    preimage
}

fn read_u8(bytes: &[u8], offset: usize, field: &'static str) -> Result<u8, ClusterError> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| err("LIFECYCLE_WIRE_MALFORMED", format!("{field} is missing")))
}

fn read_u16(bytes: &[u8], offset: usize, field: &'static str) -> Result<u16, ClusterError> {
    Ok(u16::from_be_bytes(read_array::<2>(bytes, offset, field)?))
}

fn read_u64(bytes: &[u8], offset: usize, field: &'static str) -> Result<u64, ClusterError> {
    Ok(u64::from_be_bytes(read_array::<8>(bytes, offset, field)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
    field: &'static str,
) -> Result<[u8; N], ClusterError> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| err("LIFECYCLE_WIRE_MALFORMED", "field offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| err("LIFECYCLE_WIRE_MALFORMED", format!("{field} is truncated")))?;
    let mut value = [0; N];
    value.copy_from_slice(slice);
    Ok(value)
}

/// Policy digest used by the fixed bounded lifecycle lab.
#[must_use]
pub const fn lifecycle_policy_hash() -> [u8; 32] {
    POLICY_HASH
}

/// Canonical epoch lease schedule used by deterministic lifecycle tests.
pub fn lifecycle_lease(epoch: u64) -> Result<(u64, u64), ClusterError> {
    lease_for_epoch(epoch)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn auto_report(
        node_id: LifecycleNodeId,
        state: LifecycleState,
        epoch: u64,
        commit_index: u64,
    ) -> LifecycleReport {
        let lease_expires_at_ms = if state == LifecycleState::Active {
            lease_for_epoch(epoch).expect("active lease").1
        } else {
            0
        };
        LifecycleReport {
            node_id,
            reason_code: LifecycleReasonCode::Status,
            state,
            highest_epoch: epoch,
            incarnation: 1,
            store_generation: 1,
            effect_count: 0,
            commit_index,
            state_root: expected_state_root().expect("expected root"),
            lease_expires_at_ms,
        }
    }

    #[test]
    fn command_decoder_rejects_noncanonical_unused_fields() {
        let mut bytes = LifecycleCommand {
            request_id: request_id(1),
            kind: CommandKind::Status,
            now_ms: LEASE_BASE_MS,
            epoch: 0,
            operation_id: [0; 16],
        }
        .to_bytes();
        bytes[58] = 1;
        let error = LifecycleCommand::from_bytes(&bytes).expect_err("unused field must fail");
        assert_eq!(error.reason_code(), "LIFECYCLE_COMMAND_MALFORMED");
    }

    #[test]
    fn command_signature_binds_payload_target_and_controller_key() {
        let controller = SigningKey::from_bytes(&[37; 32]);
        let command = LifecycleCommand {
            request_id: request_id(1),
            kind: CommandKind::Promote,
            now_ms: LEASE_BASE_MS,
            epoch: 1,
            operation_id: [0; 16],
        };
        let signed = SignedLifecycleCommand::sign(command, LifecycleNodeId::NodeA, &controller)
            .expect("sign command");
        let bytes = signed.to_bytes().expect("encode signed command");
        let decoded = SignedLifecycleCommand::from_bytes(&bytes).expect("decode signed command");
        decoded
            .verify(LifecycleNodeId::NodeA, &controller.verifying_key())
            .expect("verify command");

        let target_error = decoded
            .verify(LifecycleNodeId::NodeB, &controller.verifying_key())
            .expect_err("cross-node command must fail");
        assert_eq!(
            target_error.reason_code(),
            "LIFECYCLE_COMMAND_BINDING_REFUSED"
        );
        let wrong_controller = SigningKey::from_bytes(&[41; 32]);
        let key_error = decoded
            .verify(LifecycleNodeId::NodeA, &wrong_controller.verifying_key())
            .expect_err("unknown controller must fail");
        assert_eq!(key_error.reason_code(), "LIFECYCLE_COMMAND_AUTH_REFUSED");

        let mut tampered = bytes;
        tampered[34] ^= 1;
        let decoded_tamper =
            SignedLifecycleCommand::from_bytes(&tampered).expect("decode bounded tamper");
        let tamper_error = decoded_tamper
            .verify(LifecycleNodeId::NodeA, &controller.verifying_key())
            .expect_err("tampered command must fail");
        assert_eq!(tamper_error.reason_code(), "LIFECYCLE_COMMAND_AUTH_REFUSED");

        let unsigned_error = SignedLifecycleCommand::from_bytes(&command.to_bytes())
            .expect_err("unsigned legacy command must fail");
        assert_eq!(unsigned_error.reason_code(), "LIFECYCLE_COMMAND_MALFORMED");
    }

    #[test]
    fn automatic_controller_halts_on_ambiguity_and_preserves_halt_reason() {
        assert!(LifecycleAutoController::new(1).is_err());
        assert!(LifecycleAutoController::new(17).is_err());
        let mut controller = LifecycleAutoController::new(2).expect("valid policy");
        let a = auto_report(LifecycleNodeId::NodeA, LifecycleState::Active, 1, 1);
        let b = auto_report(LifecycleNodeId::NodeB, LifecycleState::Active, 1, 1);
        assert_eq!(
            controller
                .evaluate(1_001, Some(&a), Some(&b), true)
                .expect("dual-active decision"),
            LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::AmbiguousActive,
            }
        );
        assert_eq!(
            controller
                .evaluate(1_002, None, None, false)
                .expect("sticky halt"),
            LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::AmbiguousActive,
            }
        );

        let mut missed = LifecycleAutoController::new(2).expect("valid policy");
        assert_eq!(
            missed
                .evaluate(1_200, None, None, true)
                .expect("missed bootstrap window"),
            LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::PromotionWindowMissed,
            }
        );
        assert_eq!(
            missed
                .evaluate(1_100, None, None, true)
                .expect("sticky missed-window halt"),
            LifecycleAutoDecision::Halt {
                reason: LifecycleAutoReason::PromotionWindowMissed,
            }
        );
    }

    #[test]
    fn automatic_controller_refuses_wrong_slot_and_lagging_bootstrap() {
        let mut controller = LifecycleAutoController::new(2).expect("valid policy");
        let wrong = auto_report(LifecycleNodeId::NodeB, LifecycleState::Standby, 0, 1);
        let error = controller
            .evaluate(1_000, Some(&wrong), None, true)
            .expect_err("wrong report slot must fail");
        assert_eq!(error.reason_code(), "LIFECYCLE_AUTO_REPORT_REFUSED");

        let a = auto_report(LifecycleNodeId::NodeA, LifecycleState::Standby, 0, 0);
        let b = auto_report(LifecycleNodeId::NodeB, LifecycleState::Standby, 0, 1);
        assert_eq!(
            controller
                .evaluate(1_000, Some(&a), Some(&b), true)
                .expect("lagging decision"),
            LifecycleAutoDecision::Hold {
                reason: LifecycleAutoReason::CandidateLagging,
            }
        );
        let result_error = controller
            .record_promotion_result(&b)
            .expect_err("result without pending attempt must fail");
        assert_eq!(result_error.reason_code(), "LIFECYCLE_AUTO_RESULT_REFUSED");
    }

    #[test]
    fn response_signature_binds_request_and_node() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let response = SignedLifecycleResponse::sign(
            request_id(1),
            LifecycleReport {
                node_id: LifecycleNodeId::NodeA,
                reason_code: LifecycleReasonCode::Status,
                state: LifecycleState::Standby,
                highest_epoch: 0,
                incarnation: 1,
                store_generation: 2,
                effect_count: 0,
                commit_index: 1,
                state_root: expected_state_root().expect("expected root"),
                lease_expires_at_ms: 0,
            },
            &key,
        )
        .expect("sign response");
        let bytes = response.to_bytes().expect("encode response");
        let decoded = SignedLifecycleResponse::from_bytes(&bytes).expect("decode response");
        decoded
            .verify(&request_id(1), LifecycleNodeId::NodeA, &key.verifying_key())
            .expect("verify response");
        assert!(
            decoded
                .verify(&request_id(2), LifecycleNodeId::NodeA, &key.verifying_key(),)
                .is_err()
        );
    }

    #[test]
    fn lease_schedule_has_an_explicit_guard_between_epochs() {
        let (_, first_end) = lease_for_epoch(1).expect("first lease");
        let (second_start, _) = lease_for_epoch(2).expect("second lease");
        assert_eq!(second_start - first_end, LEASE_GUARD_MS);
    }
}
