use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use quorumarc_core::{
    AuthorityState as CoreAuthorityState, CommitIndex, EffectGate, Epoch,
    FenceMechanism as CoreFenceMechanism, FenceReceipt as CoreFenceReceipt,
    HealthAttestation as CoreHealthAttestation, Incarnation, LeaseGrant as CoreLeaseGrant, NodeId,
    PolicyHash, PromotionProof as CorePromotionProof, QuorumCertificate as CoreQuorumCertificate,
    SafetyPolicy, StateEvidence, StateRoot as CoreStateRoot, TrustedClock, WorkloadId,
    validate_promotion,
};
use quorumarc_rpo0::{CounterOperation, FileReplica, OperationId, ReplicatedCounter, recover_wal};
use quorumarc_runtime::{EffectOutcome, FrameCodec, TestEffectActor};
use quorumarc_store::{
    ActivationReceipt, DurableAuthorityStore, FileBackend, LeaseBounds, PromotionRecord,
    StateRoot as StoreStateRoot, VoteRecord,
};
use quorumarc_wire::{
    CanonicalId, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant, MessageId,
    PROTOCOL_VERSION, PromotionEnvelope, QuorumBinding, QuorumCertificate, SignedPromotionEnvelope,
    SignedVote, SigningKey, VerificationKeyResolver, VerifyingKey,
};

use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::path_guard::{OwnerLock, require_disjoint_store_and_file, require_keys_disjoint};
use crate::peer::RemotePeerReplica;
use crate::protocol::{
    LAB_CANDIDATE, LAB_EPOCH, LAB_INCARNATION, LAB_KEY_ID, LAB_LEASE_EXPIRES_MS, LAB_MESSAGE_ID,
    LAB_NOW_MS, LAB_PEER, LAB_POLICY_HASH, LAB_WITNESS, LAB_WORKLOAD, MAX_CLUSTER_FRAME,
    WitnessResponse, id, witness_request_digest,
};
use crate::{ClusterError, err};

/// Candidate settings for the explicit, one-shot localhost genesis.
#[derive(Clone, Debug)]
pub struct BootstrapConfig {
    pub peer_address: SocketAddr,
    pub witness_address: SocketAddr,
    pub local_wal_path: PathBuf,
    pub store_directory: PathBuf,
    pub candidate_signing_key_file: PathBuf,
    pub peer_public_key_file: PathBuf,
    pub witness_public_key_file: PathBuf,
    pub io_timeout: Duration,
    pub allow_lab_genesis: bool,
}

/// Exact evidence emitted only after one test-sink effect is recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapReport {
    pub reason_code: &'static str,
    pub commit_index: u64,
    pub value: u64,
    pub state_root: [u8; 32],
    pub promotion_digest: [u8; 32],
    pub effect_count: usize,
    pub store_generation: u64,
}

/// Performs the bounded `LAB_GENESIS_ONE_SHOT` sequence.
pub fn run_bootstrap(config: BootstrapConfig) -> Result<BootstrapReport, ClusterError> {
    if !config.allow_lab_genesis {
        return Err(err(
            "LAB_GENESIS_DISABLED",
            "explicit allow flag was not supplied",
        ));
    }
    ensure_loopback(config.peer_address)?;
    ensure_loopback(config.witness_address)?;
    if config.io_timeout.is_zero() {
        return Err(err("TIMEOUT_REFUSED", "I/O timeout is zero"));
    }

    // Bootstrap loads the candidate's own seed plus only public peer and
    // witness keys. There is no candidate-path witness SigningKey factory.
    let candidate_signing_key = load_private_seed(&config.candidate_signing_key_file)?;
    let peer_public_key = load_public_key(&config.peer_public_key_file)?;
    let witness_public_key = load_public_key(&config.witness_public_key_file)?;
    let candidate_public_key = candidate_signing_key.verifying_key();
    require_distinct_role_keys(&[
        ("candidate", &candidate_public_key),
        ("peer", &peer_public_key),
        ("witness", &witness_public_key),
    ])?;
    require_keys_disjoint(
        &[
            config.candidate_signing_key_file.as_path(),
            config.peer_public_key_file.as_path(),
            config.witness_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        Some(&config.local_wal_path),
    )?;
    require_disjoint_store_and_file(&config.store_directory, &config.local_wal_path)?;
    let _store_lock = OwnerLock::for_store(&config.store_directory, "candidate")?;
    let _wal_lock = OwnerLock::for_file(&config.local_wal_path, "candidate")?;

    let mut store = DurableAuthorityStore::open_in(&config.store_directory, FileBackend)
        .map_err(|error| err("CANDIDATE_STORE_OPEN_REFUSED", error.to_string()))?;
    require_empty_candidate_store(&store)?;
    require_empty_wal(&config.local_wal_path)?;

    let remote_signing_key = SigningKey::from_bytes(candidate_signing_key.as_bytes());
    let mut local_replica = FileReplica::new(LAB_CANDIDATE, &config.local_wal_path);
    let mut remote_replica = RemotePeerReplica::new(
        config.peer_address,
        config.io_timeout,
        remote_signing_key,
        peer_public_key,
    );
    let mut counter = ReplicatedCounter::new();
    let acknowledged = counter
        .apply(
            CounterOperation {
                id: OperationId::new([9; 16]),
                expected_commit_index: 0,
                increment: 1,
            },
            &mut local_replica,
            &mut remote_replica,
        )
        .map_err(|error| err("RPO0_WRITE_REFUSED", error.to_string()))?;
    if acknowledged.commit_index != 1 || acknowledged.value != 1 {
        return Err(err(
            "RPO0_WRITE_REFUSED",
            "one-shot write returned unexpected progress",
        ));
    }

    let provisional = provisional_envelope(
        acknowledged.commit_index,
        acknowledged.state_root,
        &candidate_signing_key,
    )?;
    let witness_response = request_witness(
        config.witness_address,
        config.io_timeout,
        &provisional,
        &witness_public_key,
    )?;
    if !witness_response.decision().is_granted() {
        return Err(err(
            "WITNESS_VOTE_REFUSED",
            "witness returned no durable authority evidence",
        ));
    }
    if witness_response.durable_generation() == 0 {
        return Err(err(
            "WITNESS_VOTE_REFUSED",
            "witness durable generation is zero",
        ));
    }
    let final_envelope = PromotionEnvelope::from_canonical_bytes(witness_response.envelope_bytes())
        .map_err(|error| err("FINAL_ENVELOPE_REFUSED", error.to_string()))?;
    exact_final_scope(
        &final_envelope,
        acknowledged.commit_index,
        acknowledged.state_root,
    )?;
    let signed =
        SignedPromotionEnvelope::sign(final_envelope, id(LAB_KEY_ID)?, &candidate_signing_key)
            .map_err(|error| err("FINAL_ENVELOPE_SIGN_FAILED", error.to_string()))?;
    let resolver = LabResolver {
        candidate_key: candidate_public_key,
        witness_key: witness_public_key,
    };

    // Cryptographic wire verification is deliberately complete before any
    // wire fields are converted into core authority evidence.
    signed
        .verify(&resolver)
        .map_err(|error| err("FINAL_ENVELOPE_AUTH_REFUSED", error.to_string()))?;
    let promotion_digest = signed
        .digest()
        .map_err(|error| err("FINAL_ENVELOPE_DIGEST_FAILED", error.to_string()))?;
    let proposal_digest = signed
        .envelope()
        .quorum_certificate
        .binding
        .proposal_digest()
        .map_err(|error| err("PROPOSAL_DIGEST_FAILED", error.to_string()))?;
    let core_proof = to_core_proof(signed.envelope())?;
    let policy = core_policy()?;
    let validated = validate_promotion(
        &core_proof,
        &CoreAuthorityState::initial(),
        &policy,
        LAB_NOW_MS,
    )
    .map_err(|error| err("CORE_PROMOTION_REFUSED", error.to_string()))?;

    // The authority store is still exactly empty at this point. Every
    // authority transition below is synchronous and checked before the fixed
    // test clock can open the in-memory EffectGate.
    store
        .allocate_incarnation(LAB_INCARNATION)
        .map_err(|error| err("INCARNATION_PERSIST_REFUSED", error.to_string()))?;
    store
        .record_vote(
            VoteRecord::new(LAB_EPOCH, LAB_CANDIDATE, proposal_digest)
                .map_err(|error| err("CANDIDATE_VOTE_INVALID", error.to_string()))?,
        )
        .map_err(|error| err("CANDIDATE_VOTE_PERSIST_REFUSED", error.to_string()))?;
    let lease = LeaseBounds::new(LAB_NOW_MS, LAB_LEASE_EXPIRES_MS)
        .map_err(|error| err("LEASE_INVALID", error.to_string()))?;
    store
        .record_promotion(
            PromotionRecord::new(
                LAB_EPOCH,
                proposal_digest,
                promotion_digest,
                lease,
                acknowledged.commit_index,
                StoreStateRoot::new(acknowledged.state_root),
            )
            .map_err(|error| err("PROMOTION_RECORD_INVALID", error.to_string()))?,
        )
        .map_err(|error| err("PROMOTION_PERSIST_REFUSED", error.to_string()))?;

    let gate = EffectGate::recover(
        core_node(LAB_CANDIDATE)?,
        core_workload()?,
        PolicyHash::new(LAB_POLICY_HASH),
        quorumarc_core::GateRecoveryState::new(Epoch(0), Incarnation(LAB_INCARNATION), 0),
        FixedClock,
    );
    let mut effects = TestEffectActor::new(gate);
    let persistence = effects
        .stage(validated)
        .map_err(|error| err("EFFECT_STAGE_REFUSED", error.to_string()))?;

    // With this immutable lab clock only, pre-commit the activation record,
    // then compare every field exposed by the core receipt before emitting one
    // effect. The core receipt does not itself carry the final-envelope digest;
    // that digest is rechecked separately in the durable state below. This API
    // limitation is one reason the path remains lab-only.
    let expected_activation = ActivationReceipt::new(
        LAB_EPOCH,
        LAB_CANDIDATE,
        LAB_INCARNATION,
        promotion_digest,
        LAB_NOW_MS,
        LAB_LEASE_EXPIRES_MS,
    )
    .map_err(|error| err("ACTIVATION_RECORD_INVALID", error.to_string()))?;
    store
        .record_activation(expected_activation)
        .map_err(|error| err("ACTIVATION_PERSIST_REFUSED", error.to_string()))?;
    require_exact_durable_state(
        &store,
        proposal_digest,
        promotion_digest,
        acknowledged.commit_index,
        acknowledged.state_root,
    )?;
    effects
        .confirm_persisted(&persistence)
        .map_err(|error| err("EFFECT_CONFIRM_REFUSED", error.to_string()))?;
    let actual_activation = effects
        .activate()
        .map_err(|error| err("EFFECT_ACTIVATE_REFUSED", error.to_string()))?;
    if actual_activation.workload.as_str() != LAB_WORKLOAD
        || actual_activation.holder.as_str() != LAB_CANDIDATE
        || actual_activation.incarnation.0 != LAB_INCARNATION
        || actual_activation.epoch.0 != LAB_EPOCH
        || actual_activation.activated_at_ms != LAB_NOW_MS
        || actual_activation.expires_at_ms != LAB_LEASE_EXPIRES_MS
        || actual_activation.durable_commit.0 != acknowledged.commit_index
        || actual_activation.state_root.as_bytes() != &acknowledged.state_root
        || actual_activation.fence_class != quorumarc_core::FenceClass::Bootstrap
        || actual_activation.policy_hash.as_bytes() != &LAB_POLICY_HASH
    {
        effects.close();
        return Err(err(
            "ACTIVATION_POSTCHECK_REFUSED",
            "actual fixed-clock core receipt differs from durable activation scope",
        ));
    }
    let outcome = effects
        .emit(
            [99; 16],
            core_node(LAB_CANDIDATE)?,
            Epoch(LAB_EPOCH),
            b"LAB_GENESIS_ONE_SHOT",
        )
        .map_err(|error| err("EFFECT_EMIT_REFUSED", error.to_string()))?;
    if outcome != EffectOutcome::Recorded || effects.records().len() != 1 {
        effects.close();
        return Err(err(
            "EFFECT_POSTCHECK_REFUSED",
            "test sink did not contain exactly one new effect",
        ));
    }
    let effect_count = effects.records().len();
    effects.close();

    Ok(BootstrapReport {
        reason_code: "LAB_GENESIS_ONE_SHOT",
        commit_index: acknowledged.commit_index,
        value: acknowledged.value,
        state_root: acknowledged.state_root,
        promotion_digest,
        effect_count,
        store_generation: store.generation(),
    })
}

fn provisional_envelope(
    commit_index: u64,
    state_root: [u8; 32],
    candidate_key: &SigningKey,
) -> Result<SignedPromotionEnvelope, ClusterError> {
    let binding = QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new(LAB_MESSAGE_ID),
        workload_id: id(LAB_WORKLOAD)?,
        candidate_node_id: id(LAB_CANDIDATE)?,
        candidate_incarnation: LAB_INCARNATION,
        epoch: LAB_EPOCH,
        policy_hash: LAB_POLICY_HASH,
        required_commit: commit_index,
        durable_commit: commit_index,
        state_root,
        lease_not_before_ms: LAB_NOW_MS,
        lease_expires_at_ms: LAB_LEASE_EXPIRES_MS,
    };
    let candidate_vote =
        SignedVote::sign(&binding, id(LAB_CANDIDATE)?, id(LAB_KEY_ID)?, candidate_key)
            .map_err(|error| err("CANDIDATE_VOTE_SIGN_FAILED", error.to_string()))?;
    let certificate = QuorumCertificate::new(binding.clone(), 1, vec![candidate_vote])
        .map_err(|error| err("PROVISIONAL_CERTIFICATE_REFUSED", error.to_string()))?;
    let provisional_fence = FenceReceipt::sign(
        &binding,
        None,
        id(LAB_CANDIDATE)?,
        id(LAB_KEY_ID)?,
        FenceMechanism::Bootstrap,
        LAB_NOW_MS.saturating_sub(5),
        [77; 32],
        candidate_key,
    )
    .map_err(|error| err("PROVISIONAL_FENCE_SIGN_FAILED", error.to_string()))?;
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
            observed_at_ms: LAB_NOW_MS.saturating_sub(2),
            attestation_digest: [17; 32],
        },
        lease: LeaseGrant {
            holder_node_id: binding.candidate_node_id,
            incarnation: binding.candidate_incarnation,
            epoch: binding.epoch,
            not_before_ms: binding.lease_not_before_ms,
            expires_at_ms: binding.lease_expires_at_ms,
        },
    };
    SignedPromotionEnvelope::sign(envelope, id(LAB_KEY_ID)?, candidate_key)
        .map_err(|error| err("PROVISIONAL_ENVELOPE_SIGN_FAILED", error.to_string()))
}

fn request_witness(
    address: SocketAddr,
    timeout: Duration,
    request: &SignedPromotionEnvelope,
    witness_key: &VerifyingKey,
) -> Result<WitnessResponse, ClusterError> {
    ensure_loopback(address)?;
    let mut stream = TcpStream::connect_timeout(&address, timeout)
        .map_err(|error| err("WITNESS_CONNECT_FAILED", format!("{address}: {error}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|error| err("SOCKET_CONFIG_FAILED", error.to_string()))?;
    let codec = FrameCodec::new(MAX_CLUSTER_FRAME)
        .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;
    let request_bytes = request
        .to_canonical_bytes()
        .map_err(|error| err("WITNESS_REQUEST_ENCODE_FAILED", error.to_string()))?;
    codec
        .write_frame(&mut stream, &request_bytes)
        .map_err(|error| err("WITNESS_FRAME_WRITE_FAILED", error.to_string()))?;
    let response_bytes = codec
        .read_frame(&mut stream)
        .map_err(|error| err("WITNESS_FRAME_REFUSED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "WITNESS_RESPONSE_MISSING",
                "witness closed without response",
            )
        })?;
    let response = WitnessResponse::from_bytes(&response_bytes)?;
    let request_digest = witness_request_digest(&request_bytes)?;
    response.verify(&request.envelope().message_id, &request_digest, witness_key)?;
    Ok(response)
}

fn exact_final_scope(
    envelope: &PromotionEnvelope,
    commit_index: u64,
    state_root: [u8; 32],
) -> Result<(), ClusterError> {
    let votes = envelope.quorum_certificate.votes();
    if envelope.message_id.as_bytes() != &LAB_MESSAGE_ID
        || envelope.workload_id.as_str() != LAB_WORKLOAD
        || envelope.candidate_node_id.as_str() != LAB_CANDIDATE
        || envelope.candidate_incarnation != LAB_INCARNATION
        || envelope.epoch != LAB_EPOCH
        || envelope.policy_hash != LAB_POLICY_HASH
        || envelope.required_commit != commit_index
        || envelope.durable_commit != commit_index
        || envelope.state_root != state_root
        || envelope.quorum_certificate.threshold != 2
        || votes.len() != 2
        || votes
            .first()
            .is_none_or(|vote| vote.voter_id().as_str() != LAB_CANDIDATE)
        || votes
            .get(1)
            .is_none_or(|vote| vote.voter_id().as_str() != LAB_WITNESS)
        || envelope.fence_receipt.verifier_id().as_str() != LAB_WITNESS
        || envelope.fence_receipt.mechanism() != FenceMechanism::Bootstrap
        || envelope.fence_receipt.target().is_some()
        || envelope.lease.not_before_ms != LAB_NOW_MS
        || envelope.lease.expires_at_ms != LAB_LEASE_EXPIRES_MS
    {
        return Err(err(
            "FINAL_SCOPE_REFUSED",
            "witness envelope left fixed LAB_GENESIS_ONE_SHOT scope",
        ));
    }
    Ok(())
}

fn to_core_proof(envelope: &PromotionEnvelope) -> Result<CorePromotionProof, ClusterError> {
    let workload = core_workload()?;
    let candidate = core_node(envelope.candidate_node_id.as_str())?;
    let policy_hash = PolicyHash::new(envelope.policy_hash);
    let state_root = CoreStateRoot::new(envelope.state_root);
    let voters = envelope
        .quorum_certificate
        .votes()
        .iter()
        .map(|vote| core_node(vote.voter_id().as_str()))
        .collect::<Result<Vec<_>, _>>()?;
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
            target: None,
            verifier: core_node(envelope.fence_receipt.verifier_id().as_str())?,
            mechanism: CoreFenceMechanism::Bootstrap,
            observed_at_ms: envelope.fence_receipt.observed_at_ms(),
        },
        state: StateEvidence {
            required_commit: CommitIndex(envelope.required_commit),
            durable_commit: CommitIndex(envelope.durable_commit),
            state_root,
            observed_at_ms: LAB_NOW_MS.saturating_sub(2),
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

fn core_policy() -> Result<SafetyPolicy, ClusterError> {
    SafetyPolicy::new(
        core_workload()?,
        PolicyHash::new(LAB_POLICY_HASH),
        [core_node(LAB_CANDIDATE)?, core_node(LAB_PEER)?],
        [
            core_node(LAB_CANDIDATE)?,
            core_node(LAB_PEER)?,
            core_node(LAB_WITNESS)?,
        ],
        2,
        Some(core_node(LAB_WITNESS)?),
        3,
        100,
        1_000,
        0,
        false,
    )
    .map_err(|error| err("CORE_POLICY_INVALID", error.to_string()))
}

fn require_empty_candidate_store(
    store: &DurableAuthorityStore<FileBackend>,
) -> Result<(), ClusterError> {
    let state = store.state();
    if store.generation() != 0
        || state.highest_epoch() != 0
        || state.incarnation() != 0
        || state.last_vote().is_some()
        || state.last_promotion().is_some()
        || state.commit_index() != 0
        || state.state_root().is_some()
        || state.activation_receipt().is_some()
    {
        return Err(err(
            "LAB_GENESIS_STORE_NOT_EMPTY",
            "local authority store is not exact empty genesis state",
        ));
    }
    Ok(())
}

fn require_empty_wal(path: &Path) -> Result<(), ClusterError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(err("WAL_READ_REFUSED", error.to_string())),
    };
    let recovered =
        recover_wal(&bytes).map_err(|error| err("WAL_RECOVERY_REFUSED", error.to_string()))?;
    if recovered.commit_index != 0 || recovered.value != 0 {
        return Err(err(
            "LAB_GENESIS_WAL_NOT_EMPTY",
            "candidate WAL is not exact empty genesis state",
        ));
    }
    Ok(())
}

fn require_exact_durable_state(
    store: &DurableAuthorityStore<FileBackend>,
    proposal_digest: [u8; 32],
    promotion_digest: [u8; 32],
    commit_index: u64,
    state_root: [u8; 32],
) -> Result<(), ClusterError> {
    let state = store.state();
    let vote = state
        .last_vote()
        .ok_or_else(|| err("DURABLE_POSTCHECK_REFUSED", "vote missing"))?;
    let promotion = state
        .last_promotion()
        .ok_or_else(|| err("DURABLE_POSTCHECK_REFUSED", "promotion missing"))?;
    let activation = state
        .activation_receipt()
        .ok_or_else(|| err("DURABLE_POSTCHECK_REFUSED", "activation missing"))?;
    if store.generation() != 4
        || state.highest_epoch() != LAB_EPOCH
        || state.incarnation() != LAB_INCARNATION
        || vote.epoch() != LAB_EPOCH
        || vote.candidate() != LAB_CANDIDATE
        || vote.proposal_digest() != &proposal_digest
        || promotion.epoch() != LAB_EPOCH
        || promotion.proposal_digest() != &proposal_digest
        || promotion.signed_envelope_digest() != &promotion_digest
        || promotion.lease().not_before_ms() != LAB_NOW_MS
        || promotion.lease().expires_at_ms() != LAB_LEASE_EXPIRES_MS
        || promotion.commit_index() != commit_index
        || promotion.state_root() != StoreStateRoot::new(state_root)
        || state.commit_index() != commit_index
        || state.state_root() != Some(StoreStateRoot::new(state_root))
        || activation.epoch() != LAB_EPOCH
        || activation.holder() != LAB_CANDIDATE
        || activation.incarnation() != LAB_INCARNATION
        || activation.promotion_digest() != &promotion_digest
        || activation.activated_at_ms() != LAB_NOW_MS
        || activation.expires_at_ms() != LAB_LEASE_EXPIRES_MS
    {
        return Err(err(
            "DURABLE_POSTCHECK_REFUSED",
            "authority state differs from exact one-shot precommit",
        ));
    }
    Ok(())
}

fn core_node(value: &str) -> Result<NodeId, ClusterError> {
    NodeId::new(value).map_err(|error| err("CORE_IDENTIFIER_INVALID", error.to_string()))
}

fn core_workload() -> Result<WorkloadId, ClusterError> {
    WorkloadId::new(LAB_WORKLOAD).map_err(|error| err("CORE_IDENTIFIER_INVALID", error.to_string()))
}

fn ensure_loopback(address: SocketAddr) -> Result<(), ClusterError> {
    if !address.ip().is_loopback() {
        return Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost lab"),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct FixedClock;

impl TrustedClock for FixedClock {
    fn now_ms(&self) -> u64 {
        LAB_NOW_MS
    }
}

struct LabResolver {
    candidate_key: VerifyingKey,
    witness_key: VerifyingKey,
}

impl VerificationKeyResolver for LabResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if key_id.as_str() != LAB_KEY_ID {
            return None;
        }
        match principal.as_str() {
            LAB_CANDIDATE => Some(self.candidate_key),
            LAB_WITNESS => Some(self.witness_key),
            _ => None,
        }
    }
}
