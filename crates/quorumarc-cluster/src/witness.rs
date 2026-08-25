use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use quorumarc_runtime::{FrameCodec, VoteReasonCode, WitnessPolicy, WitnessVoteActor};
use quorumarc_store::FileBackend;
use quorumarc_wire::{
    CanonicalId, FenceMechanism, FenceReceipt, PromotionEnvelope, QuorumCertificate,
    SignedPromotionEnvelope, SigningKey, VerificationKeyResolver, VerifyingKey,
};

use crate::keys::{load_private_seed, load_public_key, require_distinct_role_keys};
use crate::path_guard::{
    OwnerLock, prepare_store_directory, require_keys_disjoint, require_ready_disjoint,
    write_ready_file,
};
use crate::protocol::{
    LAB_CANDIDATE, LAB_EPOCH, LAB_INCARNATION, LAB_KEY_ID, LAB_LEASE_EXPIRES_MS, LAB_MESSAGE_ID,
    LAB_NOW_MS, LAB_POLICY_HASH, LAB_WITNESS, LAB_WORKLOAD, MAX_CLUSTER_FRAME, WitnessDecision,
    WitnessResponse, id, witness_request_digest,
};
use crate::{ClusterError, err};

/// Bounded localhost witness configuration.
#[derive(Clone, Debug)]
pub struct WitnessConfig {
    pub listen: SocketAddr,
    pub ready_file: PathBuf,
    pub store_directory: PathBuf,
    pub signing_key_file: PathBuf,
    pub candidate_public_key_file: PathBuf,
    pub max_connections: u64,
    pub io_timeout: Duration,
}

/// Runs the independent witness. The private seed is loaded only in this
/// function and remains inside the witness process.
pub fn serve_witness(config: WitnessConfig) -> Result<(), ClusterError> {
    ensure_loopback(config.listen)?;
    ensure_timeout(config.io_timeout)?;
    if config.max_connections == 0 {
        return Err(err("WITNESS_CONFIG_REFUSED", "connection bound is zero"));
    }
    require_keys_disjoint(
        &[
            config.signing_key_file.as_path(),
            config.candidate_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        None,
    )?;
    require_ready_disjoint(
        &config.ready_file,
        &[
            config.signing_key_file.as_path(),
            config.candidate_public_key_file.as_path(),
        ],
        Some(&config.store_directory),
        None,
    )?;
    let witness_signing_key = load_private_seed(&config.signing_key_file)?;
    let candidate_key = load_public_key(&config.candidate_public_key_file)?;
    let witness_key = witness_signing_key.verifying_key();
    require_distinct_role_keys(&[("witness", &witness_key), ("candidate", &candidate_key)])?;
    prepare_store_directory(&config.store_directory)?;
    let _store_lock = OwnerLock::for_store(&config.store_directory, "witness")?;
    let policy = WitnessPolicy::new(
        id(LAB_WITNESS)?,
        id(LAB_KEY_ID)?,
        id(LAB_WORKLOAD)?,
        LAB_POLICY_HASH,
        [id(LAB_CANDIDATE)?],
        1_000,
    )
    .map_err(|error| err("WITNESS_POLICY_INVALID", error.to_string()))?;
    let actor_key = SigningKey::from_bytes(witness_signing_key.as_bytes());
    let mut actor = WitnessVoteActor::open(policy, actor_key, &config.store_directory, FileBackend)
        .map_err(|error| err("WITNESS_STORE_OPEN_REFUSED", error.to_string()))?;
    let listener = TcpListener::bind(config.listen)
        .map_err(|error| err("WITNESS_BIND_FAILED", format!("{}: {error}", config.listen)))?;
    let local = listener
        .local_addr()
        .map_err(|error| err("WITNESS_BIND_FAILED", error.to_string()))?;
    ensure_loopback(local)?;
    let codec = FrameCodec::new(MAX_CLUSTER_FRAME)
        .map_err(|error| err("FRAME_CONFIG_FAILED", error.to_string()))?;

    // Readiness follows all key, path, owner-lock, recovery, policy, listener
    // and framing preflight checks.
    write_ready_file(&config.ready_file, &local.to_string())?;

    let resolver = CandidateResolver { candidate_key };
    for _ in 0..config.max_connections {
        let (mut stream, remote) = accept(&listener)?;
        if !remote.ip().is_loopback() {
            continue;
        }
        configure_stream(&stream, config.io_timeout)?;
        if let Err(error) = handle_witness_connection(
            &mut stream,
            codec,
            &resolver,
            &witness_signing_key,
            &mut actor,
        ) {
            eprintln!("event=witness_request {error}");
        }
    }
    Ok(())
}

fn handle_witness_connection(
    stream: &mut TcpStream,
    codec: FrameCodec,
    resolver: &CandidateResolver,
    witness_signing_key: &SigningKey,
    actor: &mut WitnessVoteActor<FileBackend>,
) -> Result<(), ClusterError> {
    let payload = codec
        .read_frame(stream)
        .map_err(|error| err("WITNESS_FRAME_REFUSED", error.to_string()))?
        .ok_or_else(|| {
            err(
                "WITNESS_REQUEST_MISSING",
                "connection closed without request",
            )
        })?;
    let request = SignedPromotionEnvelope::from_canonical_bytes(&payload)
        .map_err(|error| err("WITNESS_REQUEST_MALFORMED", error.to_string()))?;
    request
        .verify(resolver)
        .map_err(|error| err("WITNESS_REQUEST_AUTH_REFUSED", error.to_string()))?;
    let envelope = request.envelope();
    exact_provisional_scope(envelope)?;

    let reply = actor.handle_vote(&envelope.quorum_certificate.binding);
    let (decision, generation, final_bytes) = if reply.is_granted() {
        let candidate_vote = envelope
            .quorum_certificate
            .votes()
            .first()
            .ok_or_else(|| err("WITNESS_INTERNAL_REFUSED", "candidate vote missing"))?
            .clone();
        let witness_vote = reply
            .signed_vote()
            .ok_or_else(|| err("WITNESS_INTERNAL_REFUSED", "durable reply lacks vote"))?
            .clone();
        let certificate = QuorumCertificate::new(
            envelope.quorum_certificate.binding.clone(),
            2,
            vec![candidate_vote, witness_vote],
        )
        .map_err(|error| err("WITNESS_CERTIFICATE_REFUSED", error.to_string()))?;
        let fence = FenceReceipt::sign(
            &certificate.binding,
            None,
            id(LAB_WITNESS)?,
            id(LAB_KEY_ID)?,
            FenceMechanism::Bootstrap,
            LAB_NOW_MS.saturating_sub(5),
            [91; 32],
            witness_signing_key,
        )
        .map_err(|error| err("WITNESS_FENCE_SIGN_FAILED", error.to_string()))?;
        let mut final_envelope = envelope.clone();
        final_envelope.quorum_certificate = certificate;
        final_envelope.fence_receipt = fence;
        final_envelope
            .validate()
            .map_err(|error| err("WITNESS_FINAL_ENVELOPE_REFUSED", error.to_string()))?;
        let bytes = final_envelope
            .to_canonical_bytes()
            .map_err(|error| err("WITNESS_FINAL_ENVELOPE_REFUSED", error.to_string()))?;
        let decision = match reply.code() {
            VoteReasonCode::GrantedDurablyRecorded => WitnessDecision::DurableGrant,
            VoteReasonCode::GrantedAlreadyDurable => WitnessDecision::DurableRetry,
            _ => {
                return Err(err(
                    "WITNESS_INTERNAL_REFUSED",
                    "granted reply carried refusal code",
                ));
            }
        };
        let generation = reply
            .durable_generation()
            .ok_or_else(|| err("WITNESS_INTERNAL_REFUSED", "durable reply lacks generation"))?;
        (decision, generation, bytes)
    } else {
        (WitnessDecision::Refused, 0, Vec::new())
    };
    let response = WitnessResponse::sign(
        envelope.message_id,
        witness_request_digest(&payload)?,
        decision,
        generation,
        final_bytes,
        witness_signing_key,
    )?;
    codec
        .write_frame(stream, &response.to_bytes()?)
        .map_err(|error| err("WITNESS_FRAME_WRITE_FAILED", error.to_string()))?;
    eprintln!("event=witness_vote code={decision:?} durable_generation={generation}");
    Ok(())
}

fn exact_provisional_scope(envelope: &PromotionEnvelope) -> Result<(), ClusterError> {
    let binding = &envelope.quorum_certificate.binding;
    let vote = envelope
        .quorum_certificate
        .votes()
        .first()
        .ok_or_else(|| err("WITNESS_SCOPE_REFUSED", "candidate vote missing"))?;
    if envelope.message_id.as_bytes() != &LAB_MESSAGE_ID
        || envelope.workload_id.as_str() != LAB_WORKLOAD
        || envelope.candidate_node_id.as_str() != LAB_CANDIDATE
        || envelope.candidate_incarnation != LAB_INCARNATION
        || envelope.epoch != LAB_EPOCH
        || envelope.policy_hash != LAB_POLICY_HASH
        || envelope.required_commit != 1
        || envelope.durable_commit != 1
        || envelope.state_root.iter().all(|byte| *byte == 0)
        || envelope.lease.not_before_ms != LAB_NOW_MS
        || envelope.lease.expires_at_ms != LAB_LEASE_EXPIRES_MS
        || envelope.quorum_certificate.threshold != 1
        || envelope.quorum_certificate.votes().len() != 1
        || vote.voter_id().as_str() != LAB_CANDIDATE
        || vote.key_id().as_str() != LAB_KEY_ID
        || envelope.fence_receipt.verifier_id().as_str() != LAB_CANDIDATE
        || envelope.fence_receipt.key_id().as_str() != LAB_KEY_ID
        || envelope.fence_receipt.mechanism() != FenceMechanism::Bootstrap
        || envelope.fence_receipt.target().is_some()
        || binding.message_id != envelope.message_id
    {
        return Err(err(
            "WITNESS_SCOPE_REFUSED",
            "request is outside fixed epoch1/node-a/incarnation7/orders lab scope",
        ));
    }
    Ok(())
}

struct CandidateResolver {
    candidate_key: VerifyingKey,
}

impl VerificationKeyResolver for CandidateResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if principal.as_str() == LAB_CANDIDATE && key_id.as_str() == LAB_KEY_ID {
            Some(self.candidate_key)
        } else {
            None
        }
    }
}

fn accept(listener: &TcpListener) -> Result<(TcpStream, SocketAddr), ClusterError> {
    loop {
        match listener.accept() {
            Ok(connection) => return Ok(connection),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(err("WITNESS_ACCEPT_FAILED", error.to_string())),
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

fn ensure_loopback(address: SocketAddr) -> Result<(), ClusterError> {
    if !address.ip().is_loopback() {
        return Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost lab"),
        ));
    }
    Ok(())
}

fn ensure_timeout(timeout: Duration) -> Result<(), ClusterError> {
    if timeout.is_zero() {
        return Err(err("TIMEOUT_REFUSED", "I/O timeout is zero"));
    }
    Ok(())
}
