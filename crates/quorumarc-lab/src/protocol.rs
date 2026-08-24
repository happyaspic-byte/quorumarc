use std::error::Error;
use std::fmt::{self, Display, Formatter};

use ed25519_dalek::{Signature, Signer};
use quorumarc_runtime::{VoteReasonCode, VoteReply};
use quorumarc_wire::{
    CanonicalId, EnvelopeError, MessageId, PROTOCOL_VERSION, QuorumBinding, SigningKey,
    VerifyingKey,
};

const REQUEST_MAGIC: &[u8; 8] = b"QARCVRQ\0";
const RESPONSE_MAGIC: &[u8; 8] = b"QARCVRS\0";
const REQUEST_SIGNATURE_DOMAIN: &[u8] = b"quorumarc/lab-vote-request/ed25519/v1\0";

/// Defensive allocation bound for one localhost lab payload.
pub const MAX_LAB_FRAME_SIZE: usize = 4_096;

/// Explicit idempotency identifier for one TCP request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Constructs a non-zero request ID.
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(ProtocolError::ZeroRequestId);
        }
        Ok(Self(bytes))
    }

    /// Returns the fixed-width ID bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Resolves an admitted candidate's request-authentication key.
pub trait PeerKeyResolver {
    /// Returns a currently trusted key, or `None` for unknown or retired keys.
    fn resolve_candidate_key(
        &self,
        candidate: &CanonicalId,
        key_id: &CanonicalId,
    ) -> Option<VerifyingKey>;
}

/// Candidate-authenticated request for a durable witness vote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteRequest {
    request_id: RequestId,
    binding: QuorumBinding,
    key_id: CanonicalId,
    signature: [u8; 64],
}

impl VoteRequest {
    /// Signs a fixed-schema request under a lab-specific domain separator.
    pub fn sign(
        request_id: RequestId,
        binding: QuorumBinding,
        key_id: CanonicalId,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let unsigned = encode_request_unsigned(request_id, &binding, &key_id)?;
        let signature = signing_key
            .sign(&domain_preimage(REQUEST_SIGNATURE_DOMAIN, &unsigned))
            .to_bytes();
        Ok(Self {
            request_id,
            binding,
            key_id,
            signature,
        })
    }

    /// Strictly decodes one complete request and rejects every trailing byte.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        enforce_size(bytes.len())?;
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *REQUEST_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        validate_version(reader.read_u16()?)?;
        let request_id = RequestId::new(reader.read_array::<16>()?)?;
        let binding = decode_binding(&mut reader)?;
        let key_id = reader.read_id()?;
        let signature = reader.read_array::<64>()?;
        reader.finish()?;
        Ok(Self {
            request_id,
            binding,
            key_id,
            signature,
        })
    }

    /// Serializes one request in its deterministic fixed schema.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = encode_request_unsigned(self.request_id, &self.binding, &self.key_id)?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(bytes.len())?;
        Ok(bytes)
    }

    /// Verifies candidate identity, rotation-aware key ID, and request signature.
    pub fn verify<R: PeerKeyResolver>(&self, resolver: &R) -> Result<(), ProtocolError> {
        let key = resolver
            .resolve_candidate_key(&self.binding.candidate_node_id, &self.key_id)
            .ok_or_else(|| ProtocolError::UnknownCandidateKey {
                candidate: self.binding.candidate_node_id.as_str().to_owned(),
                key_id: self.key_id.as_str().to_owned(),
            })?;
        let unsigned = encode_request_unsigned(self.request_id, &self.binding, &self.key_id)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(
            &domain_preimage(REQUEST_SIGNATURE_DOMAIN, &unsigned),
            &signature,
        )
        .map_err(|_| ProtocolError::InvalidRequestSignature)
    }

    /// Network request ID echoed in the response.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Exact promotion binding passed to the witness actor after authentication.
    #[must_use]
    pub const fn binding(&self) -> &QuorumBinding {
        &self.binding
    }
}

/// Stable decision code carried over the lab transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionCode {
    /// New vote was durably recorded before reply.
    GrantedDurablyRecorded,
    /// Exact binding was already durable.
    GrantedAlreadyDurable,
    /// Candidate authentication failed before the witness actor ran.
    RefusedAuthentication,
    /// Binding was structurally invalid.
    RefusedMalformedBinding,
    /// Workload did not match witness policy.
    RefusedWorkloadMismatch,
    /// Policy digest did not match witness policy.
    RefusedPolicyMismatch,
    /// Candidate was not admitted.
    RefusedCandidateNotAllowed,
    /// Requested lease exceeded policy.
    RefusedLeaseTooLong,
    /// Epoch was below durable witness state.
    RefusedStaleEpoch,
    /// Another binding was already durable at this epoch.
    RefusedConflictSameEpoch,
    /// Epoch was accepted by another durable transition.
    RefusedEpochAlreadyAccepted,
    /// An earlier storage error poisoned the actor.
    RefusedStorePoisoned,
    /// Durable storage I/O failed.
    RefusedDurabilityIo,
    /// Durable state contradicted actor invariants.
    RefusedStoreInvariant,
    /// Durable generation could not advance.
    RefusedGenerationExhausted,
    /// Signing failed after durability.
    RefusedSigningFailure,
}

impl DecisionCode {
    /// Whether this is witness vote evidence. It is never full authority.
    #[must_use]
    pub const fn is_granted(self) -> bool {
        matches!(
            self,
            Self::GrantedDurablyRecorded | Self::GrantedAlreadyDurable
        )
    }

    /// Stable structured-log spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GrantedDurablyRecorded => "VOTE_GRANTED_DURABLY_RECORDED",
            Self::GrantedAlreadyDurable => "VOTE_GRANTED_ALREADY_DURABLE",
            Self::RefusedAuthentication => "VOTE_REFUSED_AUTHENTICATION",
            Self::RefusedMalformedBinding => "VOTE_REFUSED_MALFORMED_BINDING",
            Self::RefusedWorkloadMismatch => "VOTE_REFUSED_WORKLOAD_MISMATCH",
            Self::RefusedPolicyMismatch => "VOTE_REFUSED_POLICY_MISMATCH",
            Self::RefusedCandidateNotAllowed => "VOTE_REFUSED_CANDIDATE_NOT_ALLOWED",
            Self::RefusedLeaseTooLong => "VOTE_REFUSED_LEASE_TOO_LONG",
            Self::RefusedStaleEpoch => "VOTE_REFUSED_STALE_EPOCH",
            Self::RefusedConflictSameEpoch => "VOTE_REFUSED_CONFLICT_SAME_EPOCH",
            Self::RefusedEpochAlreadyAccepted => "VOTE_REFUSED_EPOCH_ALREADY_ACCEPTED",
            Self::RefusedStorePoisoned => "VOTE_REFUSED_STORE_POISONED",
            Self::RefusedDurabilityIo => "VOTE_REFUSED_DURABILITY_IO",
            Self::RefusedStoreInvariant => "VOTE_REFUSED_STORE_INVARIANT",
            Self::RefusedGenerationExhausted => "VOTE_REFUSED_GENERATION_EXHAUSTED",
            Self::RefusedSigningFailure => "VOTE_REFUSED_SIGNING_FAILURE",
        }
    }

    const fn tag(self) -> u16 {
        match self {
            Self::GrantedDurablyRecorded => 1,
            Self::GrantedAlreadyDurable => 2,
            Self::RefusedAuthentication => 100,
            Self::RefusedMalformedBinding => 101,
            Self::RefusedWorkloadMismatch => 102,
            Self::RefusedPolicyMismatch => 103,
            Self::RefusedCandidateNotAllowed => 104,
            Self::RefusedLeaseTooLong => 105,
            Self::RefusedStaleEpoch => 106,
            Self::RefusedConflictSameEpoch => 107,
            Self::RefusedEpochAlreadyAccepted => 108,
            Self::RefusedStorePoisoned => 109,
            Self::RefusedDurabilityIo => 110,
            Self::RefusedStoreInvariant => 111,
            Self::RefusedGenerationExhausted => 112,
            Self::RefusedSigningFailure => 113,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
        match tag {
            1 => Ok(Self::GrantedDurablyRecorded),
            2 => Ok(Self::GrantedAlreadyDurable),
            100 => Ok(Self::RefusedAuthentication),
            101 => Ok(Self::RefusedMalformedBinding),
            102 => Ok(Self::RefusedWorkloadMismatch),
            103 => Ok(Self::RefusedPolicyMismatch),
            104 => Ok(Self::RefusedCandidateNotAllowed),
            105 => Ok(Self::RefusedLeaseTooLong),
            106 => Ok(Self::RefusedStaleEpoch),
            107 => Ok(Self::RefusedConflictSameEpoch),
            108 => Ok(Self::RefusedEpochAlreadyAccepted),
            109 => Ok(Self::RefusedStorePoisoned),
            110 => Ok(Self::RefusedDurabilityIo),
            111 => Ok(Self::RefusedStoreInvariant),
            112 => Ok(Self::RefusedGenerationExhausted),
            113 => Ok(Self::RefusedSigningFailure),
            _ => Err(ProtocolError::UnknownDecisionCode(tag)),
        }
    }

    pub(crate) const fn from_vote(code: VoteReasonCode) -> Self {
        match code {
            VoteReasonCode::GrantedDurablyRecorded => Self::GrantedDurablyRecorded,
            VoteReasonCode::GrantedAlreadyDurable => Self::GrantedAlreadyDurable,
            VoteReasonCode::RefusedMalformedBinding => Self::RefusedMalformedBinding,
            VoteReasonCode::RefusedWorkloadMismatch => Self::RefusedWorkloadMismatch,
            VoteReasonCode::RefusedPolicyMismatch => Self::RefusedPolicyMismatch,
            VoteReasonCode::RefusedCandidateNotAllowed => Self::RefusedCandidateNotAllowed,
            VoteReasonCode::RefusedLeaseTooLong => Self::RefusedLeaseTooLong,
            VoteReasonCode::RefusedStaleEpoch => Self::RefusedStaleEpoch,
            VoteReasonCode::RefusedConflictSameEpoch => Self::RefusedConflictSameEpoch,
            VoteReasonCode::RefusedEpochAlreadyAccepted => Self::RefusedEpochAlreadyAccepted,
            VoteReasonCode::RefusedStorePoisoned => Self::RefusedStorePoisoned,
            VoteReasonCode::RefusedDurabilityIo => Self::RefusedDurabilityIo,
            VoteReasonCode::RefusedStoreInvariant => Self::RefusedStoreInvariant,
            VoteReasonCode::RefusedGenerationExhausted => Self::RefusedGenerationExhausted,
            VoteReasonCode::RefusedSigningFailure => Self::RefusedSigningFailure,
        }
    }
}

/// Public, deterministic subset of a signed wire vote.
///
/// `quorumarc-wire` deliberately has no unchecked constructor for a received
/// [`quorumarc_wire::SignedVote`]. Therefore this transport exposes the raw
/// fields for inspection but does not claim to reconstruct a verified proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteProof {
    voter_id: CanonicalId,
    key_id: CanonicalId,
    signature: [u8; 64],
}

impl VoteProof {
    /// Witness identity that signed the binding.
    #[must_use]
    pub const fn voter_id(&self) -> &CanonicalId {
        &self.voter_id
    }

    /// Rotation-aware witness key identifier.
    #[must_use]
    pub const fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    /// Raw Ed25519 signature bytes.
    #[must_use]
    pub const fn signature_bytes(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// One witness service reply, correlated to an exact request ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteResponse {
    request_id: RequestId,
    code: DecisionCode,
    durable_generation: Option<u64>,
    vote: Option<VoteProof>,
}

impl VoteResponse {
    pub(crate) fn from_actor(request_id: RequestId, reply: &VoteReply) -> Self {
        let vote = reply.signed_vote().map(|signed| VoteProof {
            voter_id: signed.voter_id().clone(),
            key_id: signed.key_id().clone(),
            signature: *signed.signature_bytes(),
        });
        Self {
            request_id,
            code: DecisionCode::from_vote(reply.code()),
            durable_generation: reply.durable_generation(),
            vote,
        }
    }

    pub(crate) const fn authentication_refused(request_id: RequestId) -> Self {
        Self {
            request_id,
            code: DecisionCode::RefusedAuthentication,
            durable_generation: None,
            vote: None,
        }
    }

    /// Strictly decodes one complete response.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        enforce_size(bytes.len())?;
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *RESPONSE_MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }
        validate_version(reader.read_u16()?)?;
        let request_id = RequestId::new(reader.read_array::<16>()?)?;
        let code = DecisionCode::from_tag(reader.read_u16()?)?;
        let durable_generation = match reader.read_u8()? {
            0 => None,
            1 => Some(reader.read_u64()?),
            tag => return Err(ProtocolError::UnknownOptionTag(tag)),
        };
        let vote = match reader.read_u8()? {
            0 => None,
            1 => Some(VoteProof {
                voter_id: reader.read_id()?,
                key_id: reader.read_id()?,
                signature: reader.read_array::<64>()?,
            }),
            tag => return Err(ProtocolError::UnknownOptionTag(tag)),
        };
        reader.finish()?;
        let response = Self {
            request_id,
            code,
            durable_generation,
            vote,
        };
        response.validate_shape()?;
        Ok(response)
    }

    /// Serializes one response in its deterministic fixed schema.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate_shape()?;
        let mut writer = Writer::new();
        writer.put_bytes(RESPONSE_MAGIC);
        writer.put_u16(PROTOCOL_VERSION);
        writer.put_bytes(self.request_id.as_bytes());
        writer.put_u16(self.code.tag());
        match self.durable_generation {
            Some(generation) => {
                writer.put_u8(1);
                writer.put_u64(generation);
            }
            None => writer.put_u8(0),
        }
        match &self.vote {
            Some(vote) => {
                writer.put_u8(1);
                writer.put_id(&vote.voter_id)?;
                writer.put_id(&vote.key_id)?;
                writer.put_bytes(&vote.signature);
            }
            None => writer.put_u8(0),
        }
        writer.finish()
    }

    /// Echoed request identifier.
    #[must_use]
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Stable witness decision.
    #[must_use]
    pub const fn code(&self) -> DecisionCode {
        self.code
    }

    /// Durable snapshot generation, present only for a grant.
    #[must_use]
    pub const fn durable_generation(&self) -> Option<u64> {
        self.durable_generation
    }

    /// Signed vote field subset, present only for a grant.
    #[must_use]
    pub const fn vote(&self) -> Option<&VoteProof> {
        self.vote.as_ref()
    }

    fn validate_shape(&self) -> Result<(), ProtocolError> {
        if self.code.is_granted() {
            if self.durable_generation.is_none() || self.vote.is_none() {
                return Err(ProtocolError::InconsistentResponse);
            }
        } else if self.durable_generation.is_some() || self.vote.is_some() {
            return Err(ProtocolError::InconsistentResponse);
        }
        Ok(())
    }
}

fn encode_request_unsigned(
    request_id: RequestId,
    binding: &QuorumBinding,
    key_id: &CanonicalId,
) -> Result<Vec<u8>, ProtocolError> {
    let mut writer = Writer::new();
    writer.put_bytes(REQUEST_MAGIC);
    writer.put_u16(PROTOCOL_VERSION);
    writer.put_bytes(request_id.as_bytes());
    encode_binding(&mut writer, binding)?;
    writer.put_id(key_id)?;
    writer.finish()
}

fn encode_binding(writer: &mut Writer, binding: &QuorumBinding) -> Result<(), ProtocolError> {
    writer.put_u16(binding.protocol_version);
    writer.put_bytes(binding.message_id.as_bytes());
    writer.put_id(&binding.workload_id)?;
    writer.put_id(&binding.candidate_node_id)?;
    writer.put_u64(binding.candidate_incarnation);
    writer.put_u64(binding.epoch);
    writer.put_bytes(&binding.policy_hash);
    writer.put_u64(binding.required_commit);
    writer.put_u64(binding.durable_commit);
    writer.put_bytes(&binding.state_root);
    writer.put_u64(binding.lease_not_before_ms);
    writer.put_u64(binding.lease_expires_at_ms);
    Ok(())
}

fn decode_binding(reader: &mut Reader<'_>) -> Result<QuorumBinding, ProtocolError> {
    let protocol_version = reader.read_u16()?;
    validate_version(protocol_version)?;
    Ok(QuorumBinding {
        protocol_version,
        message_id: MessageId::new(reader.read_array::<16>()?),
        workload_id: reader.read_id()?,
        candidate_node_id: reader.read_id()?,
        candidate_incarnation: reader.read_u64()?,
        epoch: reader.read_u64()?,
        policy_hash: reader.read_array::<32>()?,
        required_commit: reader.read_u64()?,
        durable_commit: reader.read_u64()?,
        state_root: reader.read_array::<32>()?,
        lease_not_before_ms: reader.read_u64()?,
        lease_expires_at_ms: reader.read_u64()?,
    })
}

fn validate_version(version: u16) -> Result<(), ProtocolError> {
    if version == PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::UnsupportedVersion(version))
    }
}

fn enforce_size(actual: usize) -> Result<(), ProtocolError> {
    if actual > MAX_LAB_FRAME_SIZE {
        Err(ProtocolError::SizeLimitExceeded {
            actual,
            maximum: MAX_LAB_FRAME_SIZE,
        })
    } else {
        Ok(())
    }
}

fn domain_preimage(domain: &[u8], statement: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(domain.len().saturating_add(statement.len()));
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(statement);
    bytes
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn put_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn put_u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn put_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn put_bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn put_id(&mut self, identifier: &CanonicalId) -> Result<(), ProtocolError> {
        let length = u16::try_from(identifier.as_str().len())
            .map_err(|_| ProtocolError::LengthOverflow)?;
        self.put_u16(length);
        self.put_bytes(identifier.as_str().as_bytes());
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, ProtocolError> {
        enforce_size(self.bytes.len())?;
        Ok(self.bytes)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_id(&mut self) -> Result<CanonicalId, ProtocolError> {
        let length = usize::from(self.read_u16()?);
        let text = std::str::from_utf8(self.take(length)?).map_err(|_| ProtocolError::InvalidUtf8)?;
        CanonicalId::new(text).map_err(ProtocolError::InvalidIdentifier)
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

/// Strict request or response codec failure.
#[derive(Debug)]
pub enum ProtocolError {
    /// Input ended before the fixed schema completed.
    Truncated,
    /// Magic bytes did not identify the expected message type.
    InvalidMagic,
    /// Only exact protocol version 1 is admitted.
    UnsupportedVersion(u16),
    /// A request ID used the all-zero replay sentinel.
    ZeroRequestId,
    /// Input was not canonical UTF-8.
    InvalidUtf8,
    /// Canonical identifier validation failed.
    InvalidIdentifier(EnvelopeError),
    /// Fixed-width length conversion failed.
    LengthOverflow,
    /// Payload exceeded the defensive bound.
    SizeLimitExceeded {
        /// Supplied payload length.
        actual: usize,
        /// Maximum admitted length.
        maximum: usize,
    },
    /// An unknown response decision tag was received.
    UnknownDecisionCode(u16),
    /// An option used a tag other than zero or one.
    UnknownOptionTag(u8),
    /// Grant/refusal fields contradicted the decision.
    InconsistentResponse,
    /// Unknown bytes remained after the fixed schema.
    TrailingBytes,
    /// Candidate/key pair was not admitted.
    UnknownCandidateKey {
        /// Claimed candidate.
        candidate: String,
        /// Claimed key identifier.
        key_id: String,
    },
    /// Candidate request signature failed strict Ed25519 verification.
    InvalidRequestSignature,
}

impl Display for ProtocolError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("lab protocol message was truncated"),
            Self::InvalidMagic => formatter.write_str("lab protocol magic was invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported lab protocol version {version}")
            }
            Self::ZeroRequestId => formatter.write_str("lab request ID was the zero sentinel"),
            Self::InvalidUtf8 => formatter.write_str("lab identifier was not UTF-8"),
            Self::InvalidIdentifier(error) => write!(formatter, "invalid lab identifier: {error}"),
            Self::LengthOverflow => formatter.write_str("lab protocol length overflow"),
            Self::SizeLimitExceeded { actual, maximum } => write!(
                formatter,
                "lab payload length {actual} exceeds maximum {maximum}"
            ),
            Self::UnknownDecisionCode(tag) => {
                write!(formatter, "unknown lab decision code {tag}")
            }
            Self::UnknownOptionTag(tag) => write!(formatter, "unknown lab option tag {tag}"),
            Self::InconsistentResponse => {
                formatter.write_str("lab response fields contradict its decision")
            }
            Self::TrailingBytes => formatter.write_str("lab protocol message had trailing bytes"),
            Self::UnknownCandidateKey { candidate, key_id } => write!(
                formatter,
                "unknown lab candidate key {candidate}/{key_id}"
            ),
            Self::InvalidRequestSignature => {
                formatter.write_str("lab candidate request signature was invalid")
            }
        }
    }
}

impl Error for ProtocolError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidIdentifier(error) => Some(error),
            _ => None,
        }
    }
}
