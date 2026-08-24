use crate::EnvelopeError;
use crate::crypto::SignedPromotionEnvelope;
use crate::model::{
    CanonicalId, FenceMechanism, FenceReceipt, HealthAttestation, LeaseGrant, MessageId,
    PROTOCOL_VERSION, PromotionEnvelope, QuorumBinding, QuorumCertificate, SignedVote,
};

const ENVELOPE_MAGIC: &[u8; 8] = b"QARCENV\0";
const SIGNED_MAGIC: &[u8; 8] = b"QARCSIG\0";

/// Maximum accepted bytes for an unsigned canonical promotion envelope.
pub const MAX_ENVELOPE_SIZE: usize = 49_152;
/// Maximum accepted bytes for a signed canonical promotion envelope.
pub const MAX_SIGNED_ENVELOPE_SIZE: usize = 65_536;

impl PromotionEnvelope {
    /// Serializes this envelope in the fixed, big-endian Gate 1 canonical format.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.put_bytes(ENVELOPE_MAGIC);
        writer.put_u16(self.protocol_version);
        writer.put_bytes(self.message_id.as_bytes());
        writer.put_id(&self.workload_id)?;
        writer.put_id(&self.candidate_node_id)?;
        writer.put_u64(self.candidate_incarnation);
        writer.put_u64(self.epoch);
        writer.put_bytes(&self.policy_hash);
        encode_certificate(&mut writer, &self.quorum_certificate)?;
        encode_fence_receipt(&mut writer, &self.fence_receipt)?;
        writer.put_u64(self.required_commit);
        writer.put_u64(self.durable_commit);
        writer.put_bytes(&self.state_root);
        encode_health(&mut writer, &self.health_attestation)?;
        encode_lease(&mut writer, &self.lease)?;
        writer.finish(MAX_ENVELOPE_SIZE)
    }

    /// Strictly decodes a fixed-schema envelope and rejects unknown trailing fields.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        enforce_size(bytes.len(), MAX_ENVELOPE_SIZE)?;
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *ENVELOPE_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }
        let protocol_version = reader.read_u16()?;
        crate::model::validate_version(protocol_version)?;
        let message_id = MessageId::new(reader.read_array::<16>()?);
        let workload_id = reader.read_id()?;
        let candidate_node_id = reader.read_id()?;
        let candidate_incarnation = reader.read_u64()?;
        let epoch = reader.read_u64()?;
        let policy_hash = reader.read_array::<32>()?;
        let quorum_certificate = decode_certificate(&mut reader)?;
        let fence_receipt = decode_fence_receipt(&mut reader)?;
        let required_commit = reader.read_u64()?;
        let durable_commit = reader.read_u64()?;
        let state_root = reader.read_array::<32>()?;
        let health_attestation = decode_health(&mut reader)?;
        let lease = decode_lease(&mut reader)?;
        reader.finish()?;
        let envelope = Self {
            protocol_version,
            message_id,
            workload_id,
            candidate_node_id,
            candidate_incarnation,
            epoch,
            policy_hash,
            quorum_certificate,
            fence_receipt,
            required_commit,
            durable_commit,
            state_root,
            health_attestation,
            lease,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

impl SignedPromotionEnvelope {
    /// Serializes the candidate-signed envelope in its canonical outer frame.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate_structure()?;
        let envelope_bytes = self.envelope().to_canonical_bytes()?;
        let mut writer = Writer::new();
        writer.put_bytes(SIGNED_MAGIC);
        writer.put_u16(PROTOCOL_VERSION);
        writer.put_len_u32(envelope_bytes.len())?;
        writer.put_bytes(&envelope_bytes);
        writer.put_id(self.signer_id())?;
        writer.put_id(self.key_id())?;
        writer.put_bytes(self.signature_bytes());
        writer.finish(MAX_SIGNED_ENVELOPE_SIZE)
    }

    /// Strictly decodes a signed frame without treating decoding as authentication.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        enforce_size(bytes.len(), MAX_SIGNED_ENVELOPE_SIZE)?;
        let mut reader = Reader::new(bytes);
        if reader.read_array::<8>()? != *SIGNED_MAGIC {
            return Err(EnvelopeError::InvalidMagic);
        }
        let frame_version = reader.read_u16()?;
        crate::model::validate_version(frame_version)?;
        let envelope_length = reader.read_u32_as_usize()?;
        if envelope_length > MAX_ENVELOPE_SIZE {
            return Err(EnvelopeError::SizeLimitExceeded {
                actual: envelope_length,
                maximum: MAX_ENVELOPE_SIZE,
            });
        }
        let envelope = PromotionEnvelope::from_canonical_bytes(reader.take(envelope_length)?)?;
        let signer_id = reader.read_id()?;
        let key_id = reader.read_id()?;
        let signature = reader.read_array::<64>()?;
        reader.finish()?;
        let signed = Self::from_parts(envelope, signer_id, key_id, signature);
        signed.validate_structure()?;
        Ok(signed)
    }
}

pub(crate) fn encode_vote_statement(
    binding: &QuorumBinding,
    voter_id: &CanonicalId,
    key_id: &CanonicalId,
) -> Result<Vec<u8>, EnvelopeError> {
    binding.validate()?;
    let mut writer = Writer::new();
    encode_binding(&mut writer, binding)?;
    writer.put_id(voter_id)?;
    writer.put_id(key_id)?;
    writer.finish(MAX_ENVELOPE_SIZE)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn encode_fence_statement(
    binding: &QuorumBinding,
    target: Option<&CanonicalId>,
    verifier_id: &CanonicalId,
    key_id: &CanonicalId,
    mechanism: FenceMechanism,
    observed_at_ms: u64,
    evidence_digest: &[u8; 32],
) -> Result<Vec<u8>, EnvelopeError> {
    binding.validate()?;
    crate::model::validate_digest(evidence_digest, "fence evidence digest")?;
    let mut writer = Writer::new();
    encode_binding(&mut writer, binding)?;
    writer.put_option_id(target)?;
    writer.put_id(verifier_id)?;
    writer.put_id(key_id)?;
    writer.put_u8(mechanism.tag());
    writer.put_u64(observed_at_ms);
    writer.put_bytes(evidence_digest);
    writer.finish(MAX_ENVELOPE_SIZE)
}

pub(crate) fn encode_outer_signature_statement(
    envelope_bytes: &[u8],
    signer_id: &CanonicalId,
    key_id: &CanonicalId,
) -> Result<Vec<u8>, EnvelopeError> {
    let mut writer = Writer::new();
    writer.put_len_u32(envelope_bytes.len())?;
    writer.put_bytes(envelope_bytes);
    writer.put_id(signer_id)?;
    writer.put_id(key_id)?;
    writer.finish(MAX_SIGNED_ENVELOPE_SIZE)
}

fn encode_certificate(
    writer: &mut Writer,
    certificate: &QuorumCertificate,
) -> Result<(), EnvelopeError> {
    certificate.validate()?;
    encode_binding(writer, &certificate.binding)?;
    writer.put_u16(certificate.threshold);
    let count =
        u16::try_from(certificate.votes().len()).map_err(|_| EnvelopeError::LengthOverflow)?;
    writer.put_u16(count);
    for vote in certificate.votes() {
        writer.put_id(vote.voter_id())?;
        writer.put_id(vote.key_id())?;
        writer.put_bytes(vote.signature_bytes());
    }
    Ok(())
}

fn decode_certificate(reader: &mut Reader<'_>) -> Result<QuorumCertificate, EnvelopeError> {
    let binding = decode_binding(reader)?;
    let threshold = reader.read_u16()?;
    let count = usize::from(reader.read_u16()?);
    if count > crate::model::MAX_VOTES {
        return Err(EnvelopeError::TooManyVotes);
    }
    let mut votes = Vec::with_capacity(count);
    for _ in 0..count {
        votes.push(SignedVote {
            voter_id: reader.read_id()?,
            key_id: reader.read_id()?,
            signature: reader.read_array::<64>()?,
        });
    }
    QuorumCertificate::new(binding, threshold, votes)
}

fn encode_binding(writer: &mut Writer, binding: &QuorumBinding) -> Result<(), EnvelopeError> {
    binding.validate()?;
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

fn decode_binding(reader: &mut Reader<'_>) -> Result<QuorumBinding, EnvelopeError> {
    let binding = QuorumBinding {
        protocol_version: reader.read_u16()?,
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
    };
    binding.validate()?;
    Ok(binding)
}

fn encode_fence_receipt(writer: &mut Writer, receipt: &FenceReceipt) -> Result<(), EnvelopeError> {
    receipt.validate_structure()?;
    writer.put_option_id(receipt.target())?;
    writer.put_id(receipt.verifier_id())?;
    writer.put_id(receipt.key_id())?;
    writer.put_u8(receipt.mechanism().tag());
    writer.put_u64(receipt.observed_at_ms());
    writer.put_bytes(receipt.evidence_digest());
    writer.put_bytes(receipt.signature_bytes());
    Ok(())
}

fn decode_fence_receipt(reader: &mut Reader<'_>) -> Result<FenceReceipt, EnvelopeError> {
    let receipt = FenceReceipt {
        target: reader.read_option_id()?,
        verifier_id: reader.read_id()?,
        key_id: reader.read_id()?,
        mechanism: FenceMechanism::from_tag(reader.read_u8()?)?,
        observed_at_ms: reader.read_u64()?,
        evidence_digest: reader.read_array::<32>()?,
        signature: reader.read_array::<64>()?,
    };
    receipt.validate_structure()?;
    Ok(receipt)
}

fn encode_health(writer: &mut Writer, health: &HealthAttestation) -> Result<(), EnvelopeError> {
    writer.put_id(&health.node_id)?;
    writer.put_u64(health.incarnation);
    writer.put_u64(health.epoch);
    writer.put_u8(u8::from(health.healthy));
    writer.put_u16(health.passed_checks);
    writer.put_u64(health.observed_at_ms);
    writer.put_bytes(&health.attestation_digest);
    Ok(())
}

fn decode_health(reader: &mut Reader<'_>) -> Result<HealthAttestation, EnvelopeError> {
    Ok(HealthAttestation {
        node_id: reader.read_id()?,
        incarnation: reader.read_u64()?,
        epoch: reader.read_u64()?,
        healthy: reader.read_bool()?,
        passed_checks: reader.read_u16()?,
        observed_at_ms: reader.read_u64()?,
        attestation_digest: reader.read_array::<32>()?,
    })
}

fn encode_lease(writer: &mut Writer, lease: &LeaseGrant) -> Result<(), EnvelopeError> {
    writer.put_id(&lease.holder_node_id)?;
    writer.put_u64(lease.incarnation);
    writer.put_u64(lease.epoch);
    writer.put_u64(lease.not_before_ms);
    writer.put_u64(lease.expires_at_ms);
    Ok(())
}

fn decode_lease(reader: &mut Reader<'_>) -> Result<LeaseGrant, EnvelopeError> {
    Ok(LeaseGrant {
        holder_node_id: reader.read_id()?,
        incarnation: reader.read_u64()?,
        epoch: reader.read_u64()?,
        not_before_ms: reader.read_u64()?,
        expires_at_ms: reader.read_u64()?,
    })
}

fn enforce_size(actual: usize, maximum: usize) -> Result<(), EnvelopeError> {
    if actual > maximum {
        return Err(EnvelopeError::SizeLimitExceeded { actual, maximum });
    }
    Ok(())
}

struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
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

    fn put_len_u32(&mut self, length: usize) -> Result<(), EnvelopeError> {
        let length = u32::try_from(length).map_err(|_| EnvelopeError::LengthOverflow)?;
        self.bytes.extend_from_slice(&length.to_be_bytes());
        Ok(())
    }

    fn put_id(&mut self, value: &CanonicalId) -> Result<(), EnvelopeError> {
        let length =
            u16::try_from(value.as_str().len()).map_err(|_| EnvelopeError::LengthOverflow)?;
        self.put_u16(length);
        self.put_bytes(value.as_str().as_bytes());
        Ok(())
    }

    fn put_option_id(&mut self, value: Option<&CanonicalId>) -> Result<(), EnvelopeError> {
        if let Some(identifier) = value {
            self.put_u8(1);
            self.put_id(identifier)?;
        } else {
            self.put_u8(0);
        }
        Ok(())
    }

    fn finish(self, maximum: usize) -> Result<Vec<u8>, EnvelopeError> {
        enforce_size(self.bytes.len(), maximum)?;
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

    fn take(&mut self, length: usize) -> Result<&'a [u8], EnvelopeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(EnvelopeError::UnexpectedEnd)?;
        let Some(value) = self.bytes.get(self.position..end) else {
            return Err(EnvelopeError::UnexpectedEnd);
        };
        self.position = end;
        Ok(value)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], EnvelopeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EnvelopeError::UnexpectedEnd)
    }

    fn read_u8(&mut self) -> Result<u8, EnvelopeError> {
        let [value] = self.read_array::<1>()?;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, EnvelopeError> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u32_as_usize(&mut self) -> Result<usize, EnvelopeError> {
        let value = u32::from_be_bytes(self.read_array::<4>()?);
        usize::try_from(value).map_err(|_| EnvelopeError::LengthOverflow)
    }

    fn read_u64(&mut self) -> Result<u64, EnvelopeError> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_bool(&mut self) -> Result<bool, EnvelopeError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(EnvelopeError::InvalidBoolean(tag)),
        }
    }

    fn read_id(&mut self) -> Result<CanonicalId, EnvelopeError> {
        let length = usize::from(self.read_u16()?);
        let text =
            std::str::from_utf8(self.take(length)?).map_err(|_| EnvelopeError::InvalidUtf8)?;
        CanonicalId::new(text)
    }

    fn read_option_id(&mut self) -> Result<Option<CanonicalId>, EnvelopeError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => self.read_id().map(Some),
            tag => Err(EnvelopeError::InvalidOptionTag(tag)),
        }
    }

    fn finish(self) -> Result<(), EnvelopeError> {
        let remaining = self.bytes.len().saturating_sub(self.position);
        if remaining != 0 {
            return Err(EnvelopeError::TrailingBytes(remaining));
        }
        Ok(())
    }
}
