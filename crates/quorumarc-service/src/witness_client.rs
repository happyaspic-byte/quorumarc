use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use quorumarc_wire::{
    CanonicalId, MessageId, PROTOCOL_VERSION, ProductionQuorumCertificate, ProductionSignedVote,
    QuorumBinding, VerificationKeyResolver,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::config::ProductionConfig;
use crate::protocol::{
    ProductionFrame, ProductionFrameKind, ProductionRequest, ProductionVotePayload,
};
use crate::tls::load_mtls_client_config;
use crate::witness::{
    ProductionVoteError, ProductionVoteReply, read_private_seed, read_public_key,
};

const MAX_WITNESS_REPLY: usize = 8_192;
const MIN_IO_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessClientError {
    InvalidConfiguration,
    Transport,
    Malformed,
    AuthenticationFailed,
}

impl WitnessClientError {
    #[must_use]
    pub const fn is_node_failure_suspicion(self) -> bool {
        false
    }
}

#[derive(Clone, Debug)]
pub struct WitnessIdentity {
    witness_id: CanonicalId,
    key_id: CanonicalId,
    verifying_key: VerifyingKey,
}

impl WitnessIdentity {
    pub fn new(
        witness_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, WitnessClientError> {
        Ok(Self {
            witness_id: CanonicalId::new(witness_id.into())
                .map_err(|_error| WitnessClientError::InvalidConfiguration)?,
            key_id: CanonicalId::new(key_id.into())
                .map_err(|_error| WitnessClientError::InvalidConfiguration)?,
            verifying_key,
        })
    }

    #[must_use]
    pub const fn witness_id(&self) -> &CanonicalId {
        &self.witness_id
    }

    #[must_use]
    pub const fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    #[must_use]
    pub const fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CandidateControlError {
    InvalidConfiguration,
    KeyMaterial,
    Witness(WitnessClientError),
}

#[derive(Debug)]
pub struct ProductionCandidateControl {
    client: ProductionWitnessClient,
    witness: WitnessIdentity,
    signing_key: SigningKey,
    cluster_id: String,
    workload_id: String,
    node_id: String,
    key_id: String,
    policy_hash: [u8; 32],
}

impl ProductionCandidateControl {
    pub fn from_config(config: &ProductionConfig) -> Result<Self, CandidateControlError> {
        if config.role() != "data" {
            return Err(CandidateControlError::InvalidConfiguration);
        }
        let local_member = config
            .members()
            .iter()
            .find(|member| member.id == config.node_id())
            .ok_or(CandidateControlError::InvalidConfiguration)?;
        let seed = read_private_seed(config.signing_key())
            .map_err(|_error| CandidateControlError::KeyMaterial)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let local_public_key = read_public_key(&local_member.public_key)
            .map_err(|_error| CandidateControlError::KeyMaterial)?;
        if signing_key.verifying_key() != local_public_key {
            return Err(CandidateControlError::KeyMaterial);
        }
        let (client, witness) =
            ProductionWitnessClient::from_config(config).map_err(CandidateControlError::Witness)?;
        let mut member_keys = BTreeSet::new();
        for member in config.members() {
            let key = read_public_key(&member.public_key)
                .map_err(|_error| CandidateControlError::KeyMaterial)?;
            if !member_keys.insert(key.to_bytes()) {
                return Err(CandidateControlError::KeyMaterial);
            }
        }
        if signing_key.verifying_key() == witness.verifying_key {
            return Err(CandidateControlError::KeyMaterial);
        }
        Ok(Self {
            client,
            witness,
            signing_key,
            cluster_id: config.cluster_id().to_owned(),
            workload_id: config.workload_id().to_owned(),
            node_id: config.node_id().to_owned(),
            key_id: config.key_id().to_owned(),
            policy_hash: config.policy_hash(),
        })
    }

    pub fn request_certificate(
        &self,
        request: ProductionRequest,
    ) -> Result<ProductionQuorumCertificate, CandidateControlError> {
        if request.cluster_id != self.cluster_id
            || request.workload_id != self.workload_id
            || request.node_id != self.node_id
            || request.key_id != self.key_id
            || request.policy_hash != self.policy_hash
        {
            return Err(CandidateControlError::Witness(
                WitnessClientError::AuthenticationFailed,
            ));
        }
        let reply = self
            .client
            .request_vote(request.clone(), &self.signing_key, &self.witness)
            .map_err(CandidateControlError::Witness)?;
        assemble_production_certificate(&request, &self.signing_key, &self.witness, reply)
            .map_err(CandidateControlError::Witness)
    }
}

#[derive(Debug)]
pub struct ProductionWitnessClient {
    address: SocketAddr,
    server_name: ServerName<'static>,
    tls_config: Arc<ClientConfig>,
    io_timeout: Duration,
}

impl ProductionWitnessClient {
    pub fn new(
        address: SocketAddr,
        server_name: &str,
        tls_config: Arc<ClientConfig>,
        io_timeout: Duration,
    ) -> Result<Self, WitnessClientError> {
        if !(MIN_IO_TIMEOUT..=MAX_IO_TIMEOUT).contains(&io_timeout) {
            return Err(WitnessClientError::InvalidConfiguration);
        }
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|_error| WitnessClientError::InvalidConfiguration)?;
        Ok(Self {
            address,
            server_name,
            tls_config,
            io_timeout,
        })
    }

    pub fn from_config(
        config: &ProductionConfig,
    ) -> Result<(Self, WitnessIdentity), WitnessClientError> {
        config
            .verify_local_prerequisites()
            .map_err(|_error| WitnessClientError::InvalidConfiguration)?;
        if config.role() != "data" {
            return Err(WitnessClientError::InvalidConfiguration);
        }
        let witness_member = config
            .members()
            .iter()
            .find(|member| member.role == "witness")
            .ok_or(WitnessClientError::InvalidConfiguration)?;
        let witness_key = read_public_key(&witness_member.public_key)
            .map_err(|_error| WitnessClientError::InvalidConfiguration)?;
        let witness_identity =
            WitnessIdentity::new(&witness_member.id, &witness_member.key_id, witness_key)?;
        let tls = load_mtls_client_config(
            config.tls_certificate_chain(),
            config.tls_private_key(),
            config.tls_trusted_roots(),
        )
        .map_err(|_error| WitnessClientError::InvalidConfiguration)?;
        let client = Self::new(
            witness_member.address,
            config.tls_server_name(),
            Arc::new(tls),
            Duration::from_millis(config.tls_io_timeout_ms()),
        )?;
        Ok((client, witness_identity))
    }

    pub fn request_vote(
        &self,
        request: ProductionRequest,
        candidate_signing_key: &SigningKey,
        witness: &WitnessIdentity,
    ) -> Result<ProductionVoteReply, WitnessClientError> {
        let binding = binding_from_request(&request)?;
        let expected_cluster_id = request.cluster_id.clone();
        let frame =
            ProductionFrame::sign(ProductionFrameKind::Request, request, candidate_signing_key)
                .and_then(|frame| frame.encode())
                .map_err(|_error| WitnessClientError::Malformed)?;
        let frame_len =
            u32::try_from(frame.len()).map_err(|_error| WitnessClientError::Malformed)?;
        let stream = TcpStream::connect_timeout(&self.address, self.io_timeout)
            .map_err(|_error| WitnessClientError::Transport)?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .and_then(|()| stream.set_write_timeout(Some(self.io_timeout)))
            .map_err(|_error| WitnessClientError::Transport)?;
        let connection =
            ClientConnection::new(Arc::clone(&self.tls_config), self.server_name.clone())
                .map_err(|_error| WitnessClientError::InvalidConfiguration)?;
        let mut tls = StreamOwned::new(connection, stream);
        tls.write_all(&frame_len.to_be_bytes())
            .and_then(|()| tls.write_all(&frame))
            .and_then(|()| tls.flush())
            .map_err(|_error| WitnessClientError::Transport)?;
        let mut reply_len = [0_u8; 4];
        tls.read_exact(&mut reply_len)
            .map_err(|_error| WitnessClientError::Transport)?;
        let reply_len = usize::try_from(u32::from_be_bytes(reply_len))
            .map_err(|_error| WitnessClientError::Malformed)?;
        if reply_len == 0 || reply_len > MAX_WITNESS_REPLY {
            return Err(WitnessClientError::Malformed);
        }
        let mut reply_bytes = vec![0_u8; reply_len];
        tls.read_exact(&mut reply_bytes)
            .map_err(|_error| WitnessClientError::Transport)?;
        let reply = ProductionVoteReply::decode(&reply_bytes).map_err(map_vote_error)?;
        verify_reply(&reply, &expected_cluster_id, &binding, witness)?;
        Ok(reply)
    }
}

pub fn assemble_production_certificate(
    request: &ProductionRequest,
    candidate_signing_key: &SigningKey,
    witness: &WitnessIdentity,
    reply: ProductionVoteReply,
) -> Result<ProductionQuorumCertificate, WitnessClientError> {
    if candidate_signing_key.verifying_key() == witness.verifying_key {
        return Err(WitnessClientError::InvalidConfiguration);
    }
    let cluster_id = CanonicalId::new(request.cluster_id.clone())
        .map_err(|_error| WitnessClientError::Malformed)?;
    let candidate_id = CanonicalId::new(request.node_id.clone())
        .map_err(|_error| WitnessClientError::Malformed)?;
    let candidate_key_id =
        CanonicalId::new(request.key_id.clone()).map_err(|_error| WitnessClientError::Malformed)?;
    let binding = binding_from_request(request)?;
    verify_reply(&reply, &request.cluster_id, &binding, witness)?;
    let candidate_vote = ProductionSignedVote::sign(
        cluster_id.clone(),
        &binding,
        candidate_id.clone(),
        candidate_key_id.clone(),
        candidate_signing_key,
    )
    .map_err(|_error| WitnessClientError::Malformed)?;
    let witness_vote = reply
        .signed_vote()
        .cloned()
        .ok_or(WitnessClientError::Malformed)?;
    let mut votes = vec![candidate_vote, witness_vote];
    votes.sort_by(|left, right| left.voter_id().cmp(right.voter_id()));
    let certificate = ProductionQuorumCertificate::new(cluster_id, binding, 2, votes)
        .map_err(|_error| WitnessClientError::Malformed)?;
    let resolver = CertificateResolver {
        candidate_id,
        candidate_key_id,
        candidate_key: candidate_signing_key.verifying_key(),
        witness_id: witness.witness_id.clone(),
        witness_key_id: witness.key_id.clone(),
        witness_key: witness.verifying_key,
    };
    certificate
        .verify(&resolver)
        .map_err(|_error| WitnessClientError::AuthenticationFailed)?;
    Ok(certificate)
}

fn binding_from_request(request: &ProductionRequest) -> Result<QuorumBinding, WitnessClientError> {
    let payload = ProductionVotePayload::decode(&request.payload)
        .map_err(|_error| WitnessClientError::Malformed)?;
    Ok(QuorumBinding {
        protocol_version: PROTOCOL_VERSION,
        message_id: MessageId::new(request.request_id),
        workload_id: CanonicalId::new(request.workload_id.clone())
            .map_err(|_error| WitnessClientError::Malformed)?,
        candidate_node_id: CanonicalId::new(request.node_id.clone())
            .map_err(|_error| WitnessClientError::Malformed)?,
        candidate_incarnation: request.incarnation,
        epoch: request.epoch,
        policy_hash: request.policy_hash,
        required_commit: payload.required_commit(),
        durable_commit: request.progress_commit,
        state_root: payload.state_root(),
        lease_not_before_ms: payload.lease_not_before_ms(),
        lease_expires_at_ms: payload.lease_expires_at_ms(),
    })
}

fn verify_reply(
    reply: &ProductionVoteReply,
    expected_cluster_id: &str,
    binding: &QuorumBinding,
    witness: &WitnessIdentity,
) -> Result<(), WitnessClientError> {
    reply
        .verify_attestation(expected_cluster_id, &witness.verifying_key)
        .map_err(map_vote_error)?;
    if reply.cluster_id() != expected_cluster_id || reply.binding() != binding {
        return Err(WitnessClientError::AuthenticationFailed);
    }
    if let Some(vote) = reply.signed_vote() {
        if vote.voter_id() != &witness.witness_id || vote.key_id() != &witness.key_id {
            return Err(WitnessClientError::AuthenticationFailed);
        }
        let cluster_id = CanonicalId::new(expected_cluster_id.to_owned())
            .map_err(|_error| WitnessClientError::Malformed)?;
        vote.verify(&cluster_id, binding, &WitnessResolver(witness))
            .map_err(|_error| WitnessClientError::AuthenticationFailed)?;
    }
    Ok(())
}

fn map_vote_error(error: ProductionVoteError) -> WitnessClientError {
    match error {
        ProductionVoteError::AuthenticationFailed => WitnessClientError::AuthenticationFailed,
        ProductionVoteError::Malformed
        | ProductionVoteError::EpochJump
        | ProductionVoteError::IncarnationRollback
        | ProductionVoteError::IncarnationIo
        | ProductionVoteError::UnsupportedRuntime => WitnessClientError::Malformed,
    }
}

struct WitnessResolver<'a>(&'a WitnessIdentity);

impl VerificationKeyResolver for WitnessResolver<'_> {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        (principal == &self.0.witness_id && key_id == &self.0.key_id)
            .then_some(self.0.verifying_key)
    }
}

struct CertificateResolver {
    candidate_id: CanonicalId,
    candidate_key_id: CanonicalId,
    candidate_key: VerifyingKey,
    witness_id: CanonicalId,
    witness_key_id: CanonicalId,
    witness_key: VerifyingKey,
}

impl VerificationKeyResolver for CertificateResolver {
    fn resolve(&self, principal: &CanonicalId, key_id: &CanonicalId) -> Option<VerifyingKey> {
        if principal == &self.candidate_id && key_id == &self.candidate_key_id {
            Some(self.candidate_key)
        } else if principal == &self.witness_id && key_id == &self.witness_key_id {
            Some(self.witness_key)
        } else {
            None
        }
    }
}
