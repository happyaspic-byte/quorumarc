use ed25519_dalek::{Signature, Signer};
use quorumarc_rpo0::{OperationId, WalEntry};
use quorumarc_store::{StoreIdentity, StoreRole};
use quorumarc_wire::{CanonicalId, MessageId, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ClusterError, err};

pub(crate) const PROTOCOL_VERSION: u16 = 1;
pub(crate) const MAX_CLUSTER_FRAME: usize = 131_072;
pub(crate) const LAB_REQUEST_ID: [u8; 16] = [44; 16];
pub(crate) const LAB_MESSAGE_ID: [u8; 16] = [55; 16];
pub(crate) const LAB_KEY_ID: &str = "key-1";
pub(crate) const LAB_CLUSTER: &str = "gate1a-lab";
pub(crate) const LAB_WORKLOAD: &str = "orders";
pub(crate) const LAB_CANDIDATE: &str = "node-a";
pub(crate) const LAB_PEER: &str = "node-b";
pub(crate) const LAB_WITNESS: &str = "witness";
pub(crate) const LAB_POLICY_HASH: [u8; 32] = [5; 32];
pub(crate) const LAB_EPOCH: u64 = 1;
pub(crate) const LAB_INCARNATION: u64 = 7;
pub(crate) const LAB_NOW_MS: u64 = 10_000;
pub(crate) const LAB_LEASE_EXPIRES_MS: u64 = 10_500;
const CANDIDATE_STORE_ID: [u8; 16] = [61; 16];
const WITNESS_STORE_ID: [u8; 16] = [71; 16];

pub(crate) fn candidate_store_identity() -> Result<StoreIdentity, ClusterError> {
    StoreIdentity::new(
        LAB_CLUSTER,
        LAB_WORKLOAD,
        LAB_CANDIDATE,
        StoreRole::DataNode,
        CANDIDATE_STORE_ID,
    )
    .map_err(|error| err("CANDIDATE_STORE_IDENTITY_INVALID", error.to_string()))
}

pub(crate) fn witness_store_identity() -> Result<StoreIdentity, ClusterError> {
    StoreIdentity::new(
        LAB_CLUSTER,
        LAB_WORKLOAD,
        LAB_WITNESS,
        StoreRole::Witness,
        WITNESS_STORE_ID,
    )
    .map_err(|error| err("WITNESS_STORE_IDENTITY_INVALID", error.to_string()))
}

const PEER_REQUEST_MAGIC: &[u8; 8] = b"QACPRQ\0\0";
const PEER_RESPONSE_MAGIC: &[u8; 8] = b"QACPRS\0\0";
const WITNESS_RESPONSE_MAGIC: &[u8; 8] = b"QACWRS\0\0";
const PEER_REQUEST_DOMAIN: &[u8] = b"quorumarc/cluster/peer-request/ed25519/v1\0";
const PEER_REQUEST_DIGEST_DOMAIN: &[u8] = b"quorumarc/cluster/peer-request/sha256/v1\0";
const PEER_RESPONSE_DOMAIN: &[u8] = b"quorumarc/cluster/peer-response/ed25519/v1\0";
const WITNESS_RESPONSE_DOMAIN: &[u8] = b"quorumarc/cluster/witness-response/ed25519/v1\0";
const WITNESS_REQUEST_DIGEST_DOMAIN: &[u8] = b"quorumarc/cluster/witness-request/sha256/v1\0";
const RPO0_STATE_DOMAIN: &[u8] = b"quorumarc-rpo0-state-root-v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerRequest {
    request_id: [u8; 16],
    sender_id: CanonicalId,
    key_id: CanonicalId,
    workload_id: CanonicalId,
    policy_hash: [u8; 32],
    expected_state_root: [u8; 32],
    entry: WalEntry,
    canonical_record: Vec<u8>,
    signature: [u8; 64],
}

impl PeerRequest {
    pub(crate) fn sign(
        entry: WalEntry,
        canonical_record: Vec<u8>,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let expected_state_root = first_record_state_root(&canonical_record);
        let mut request = Self {
            request_id: LAB_REQUEST_ID,
            sender_id: id(LAB_CANDIDATE)?,
            key_id: id(LAB_KEY_ID)?,
            workload_id: id(LAB_WORKLOAD)?,
            policy_hash: LAB_POLICY_HASH,
            expected_state_root,
            entry,
            canonical_record,
            signature: [0; 64],
        };
        request.validate_shape()?;
        let unsigned = request.unsigned_bytes()?;
        request.signature = signing_key
            .sign(&domain_preimage(PEER_REQUEST_DOMAIN, &unsigned))
            .to_bytes();
        Ok(request)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        enforce_size(bytes)?;
        let mut reader = Reader::new(bytes);
        reader.expect_magic(PEER_REQUEST_MAGIC)?;
        reader.expect_version()?;
        let request_id = reader.array::<16>()?;
        let sender_id = reader.id()?;
        let key_id = reader.id()?;
        let workload_id = reader.id()?;
        let policy_hash = reader.array::<32>()?;
        let expected_state_root = reader.array::<32>()?;
        let entry = WalEntry {
            commit_index: reader.u64()?,
            operation_id: OperationId::new(reader.array::<16>()?),
            previous_value: reader.u64()?,
            increment: reader.u64()?,
            value: reader.u64()?,
        };
        let canonical_record = reader.length_bytes()?.to_vec();
        let signature = reader.array::<64>()?;
        reader.finish()?;
        let request = Self {
            request_id,
            sender_id,
            key_id,
            workload_id,
            policy_hash,
            expected_state_root,
            entry,
            canonical_record,
            signature,
        };
        request.validate_shape()?;
        Ok(request)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub(crate) fn verify(&self, key: &VerifyingKey) -> Result<(), ClusterError> {
        let unsigned = self.unsigned_bytes()?;
        key.verify_strict(
            &domain_preimage(PEER_REQUEST_DOMAIN, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| err("PEER_REQUEST_AUTH_REFUSED", "invalid candidate signature"))
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32], ClusterError> {
        let bytes = self.to_bytes()?;
        let mut digest = Sha256::new();
        digest.update(PEER_REQUEST_DIGEST_DOMAIN);
        digest.update(bytes);
        Ok(digest.finalize().into())
    }

    pub(crate) const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    pub(crate) const fn sender_id(&self) -> &CanonicalId {
        &self.sender_id
    }

    pub(crate) const fn key_id(&self) -> &CanonicalId {
        &self.key_id
    }

    pub(crate) const fn workload_id(&self) -> &CanonicalId {
        &self.workload_id
    }

    pub(crate) const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy_hash
    }

    pub(crate) const fn expected_state_root(&self) -> &[u8; 32] {
        &self.expected_state_root
    }

    pub(crate) const fn entry(&self) -> &WalEntry {
        &self.entry
    }

    pub(crate) fn canonical_record(&self) -> &[u8] {
        &self.canonical_record
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate_shape()?;
        let mut writer = Writer::new();
        writer.bytes(PEER_REQUEST_MAGIC);
        writer.u16(PROTOCOL_VERSION);
        writer.bytes(&self.request_id);
        writer.id(&self.sender_id)?;
        writer.id(&self.key_id)?;
        writer.id(&self.workload_id)?;
        writer.bytes(&self.policy_hash);
        writer.bytes(&self.expected_state_root);
        writer.u64(self.entry.commit_index);
        writer.bytes(&self.entry.operation_id.into_bytes());
        writer.u64(self.entry.previous_value);
        writer.u64(self.entry.increment);
        writer.u64(self.entry.value);
        writer.length_bytes(&self.canonical_record)?;
        writer.finish()
    }

    fn validate_shape(&self) -> Result<(), ClusterError> {
        if self.request_id.iter().all(|byte| *byte == 0) {
            return Err(err("PEER_REQUEST_MALFORMED", "zero request ID"));
        }
        if self.entry.encode() != self.canonical_record {
            return Err(err(
                "PEER_REQUEST_MALFORMED",
                "WAL fields differ from canonical record",
            ));
        }
        if self.policy_hash.iter().all(|byte| *byte == 0)
            || self.expected_state_root != first_record_state_root(&self.canonical_record)
        {
            return Err(err(
                "PEER_REQUEST_MALFORMED",
                "policy or expected state root is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerDecision {
    Durable,
    RefusedScope,
    RefusedDurability,
}

impl PeerDecision {
    const fn tag(self) -> u16 {
        match self {
            Self::Durable => 1,
            Self::RefusedScope => 100,
            Self::RefusedDurability => 101,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Durable),
            100 => Ok(Self::RefusedScope),
            101 => Ok(Self::RefusedDurability),
            _ => Err(err("PEER_RESPONSE_MALFORMED", "unknown decision code")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerResponse {
    request_id: [u8; 16],
    request_digest: [u8; 32],
    responder_id: CanonicalId,
    key_id: CanonicalId,
    workload_id: CanonicalId,
    policy_hash: [u8; 32],
    state_root: [u8; 32],
    decision: PeerDecision,
    commit_index: u64,
    record_checksum: u32,
    signature: [u8; 64],
}

impl PeerResponse {
    pub(crate) fn sign(
        request: &PeerRequest,
        decision: PeerDecision,
        commit_index: u64,
        record_checksum: u32,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut response = Self {
            request_id: *request.request_id(),
            request_digest: request.digest()?,
            responder_id: id(LAB_PEER)?,
            key_id: id(LAB_KEY_ID)?,
            workload_id: request.workload_id().clone(),
            policy_hash: *request.policy_hash(),
            state_root: *request.expected_state_root(),
            decision,
            commit_index,
            record_checksum,
            signature: [0; 64],
        };
        let unsigned = response.unsigned_bytes()?;
        response.signature = signing_key
            .sign(&domain_preimage(PEER_RESPONSE_DOMAIN, &unsigned))
            .to_bytes();
        Ok(response)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        enforce_size(bytes)?;
        let mut reader = Reader::new(bytes);
        reader.expect_magic(PEER_RESPONSE_MAGIC)?;
        reader.expect_version()?;
        let response = Self {
            request_id: reader.array::<16>()?,
            request_digest: reader.array::<32>()?,
            responder_id: reader.id()?,
            key_id: reader.id()?,
            workload_id: reader.id()?,
            policy_hash: reader.array::<32>()?,
            state_root: reader.array::<32>()?,
            decision: PeerDecision::from_tag(reader.u16()?)?,
            commit_index: reader.u64()?,
            record_checksum: reader.u32()?,
            signature: reader.array::<64>()?,
        };
        reader.finish()?;
        Ok(response)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub(crate) fn verify(
        &self,
        request: &PeerRequest,
        key: &VerifyingKey,
    ) -> Result<(), ClusterError> {
        if self.request_id != *request.request_id()
            || self.request_digest != request.digest()?
            || self.responder_id.as_str() != LAB_PEER
            || self.key_id.as_str() != LAB_KEY_ID
            || self.workload_id != *request.workload_id()
            || self.policy_hash != *request.policy_hash()
            || self.state_root != *request.expected_state_root()
        {
            return Err(err(
                "PEER_RESPONSE_BINDING_REFUSED",
                "response does not bind exact request digest and peer identity",
            ));
        }
        let unsigned = self.unsigned_bytes()?;
        key.verify_strict(
            &domain_preimage(PEER_RESPONSE_DOMAIN, &unsigned),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| err("PEER_RESPONSE_AUTH_REFUSED", "invalid peer signature"))
    }

    pub(crate) const fn decision(&self) -> PeerDecision {
        self.decision
    }

    pub(crate) const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    pub(crate) const fn record_checksum(&self) -> u32 {
        self.record_checksum
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut writer = Writer::new();
        writer.bytes(PEER_RESPONSE_MAGIC);
        writer.u16(PROTOCOL_VERSION);
        writer.bytes(&self.request_id);
        writer.bytes(&self.request_digest);
        writer.id(&self.responder_id)?;
        writer.id(&self.key_id)?;
        writer.id(&self.workload_id)?;
        writer.bytes(&self.policy_hash);
        writer.bytes(&self.state_root);
        writer.u16(self.decision.tag());
        writer.u64(self.commit_index);
        writer.u32(self.record_checksum);
        writer.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WitnessDecision {
    DurableGrant,
    DurableRetry,
    Refused,
}

impl WitnessDecision {
    const fn tag(self) -> u16 {
        match self {
            Self::DurableGrant => 1,
            Self::DurableRetry => 2,
            Self::Refused => 100,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::DurableGrant),
            2 => Ok(Self::DurableRetry),
            100 => Ok(Self::Refused),
            _ => Err(err("WITNESS_RESPONSE_MALFORMED", "unknown decision code")),
        }
    }

    pub(crate) const fn is_granted(self) -> bool {
        matches!(self, Self::DurableGrant | Self::DurableRetry)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct WitnessResponse {
    message_id: [u8; 16],
    request_digest: [u8; 32],
    witness_id: CanonicalId,
    key_id: CanonicalId,
    decision: WitnessDecision,
    durable_generation: u64,
    envelope_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl WitnessResponse {
    pub(crate) fn sign(
        message_id: MessageId,
        request_digest: [u8; 32],
        decision: WitnessDecision,
        durable_generation: u64,
        envelope_bytes: Vec<u8>,
        signing_key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut response = Self {
            message_id: *message_id.as_bytes(),
            request_digest,
            witness_id: id(LAB_WITNESS)?,
            key_id: id(LAB_KEY_ID)?,
            decision,
            durable_generation,
            envelope_bytes,
            signature: [0; 64],
        };
        response.validate_shape()?;
        response.signature = signing_key
            .sign(&domain_preimage(
                WITNESS_RESPONSE_DOMAIN,
                &response.unsigned_bytes()?,
            ))
            .to_bytes();
        Ok(response)
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        enforce_size(bytes)?;
        let mut reader = Reader::new(bytes);
        reader.expect_magic(WITNESS_RESPONSE_MAGIC)?;
        reader.expect_version()?;
        let response = Self {
            message_id: reader.array::<16>()?,
            request_digest: reader.array::<32>()?,
            witness_id: reader.id()?,
            key_id: reader.id()?,
            decision: WitnessDecision::from_tag(reader.u16()?)?,
            durable_generation: reader.u64()?,
            envelope_bytes: reader.length_bytes()?.to_vec(),
            signature: reader.array::<64>()?,
        };
        reader.finish()?;
        response.validate_shape()?;
        Ok(response)
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub(crate) fn verify(
        &self,
        expected_message_id: &MessageId,
        expected_request_digest: &[u8; 32],
        key: &VerifyingKey,
    ) -> Result<(), ClusterError> {
        if self.message_id != *expected_message_id.as_bytes()
            || self.request_digest != *expected_request_digest
            || self.witness_id.as_str() != LAB_WITNESS
            || self.key_id.as_str() != LAB_KEY_ID
        {
            return Err(err(
                "WITNESS_RESPONSE_BINDING_REFUSED",
                "witness response identity or message ID mismatch",
            ));
        }
        key.verify_strict(
            &domain_preimage(WITNESS_RESPONSE_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| err("WITNESS_RESPONSE_AUTH_REFUSED", "invalid witness signature"))
    }

    pub(crate) const fn decision(&self) -> WitnessDecision {
        self.decision
    }

    pub(crate) const fn durable_generation(&self) -> u64 {
        self.durable_generation
    }

    pub(crate) fn envelope_bytes(&self) -> &[u8] {
        &self.envelope_bytes
    }

    fn validate_shape(&self) -> Result<(), ClusterError> {
        if self.message_id.iter().all(|byte| *byte == 0) {
            return Err(err("WITNESS_RESPONSE_MALFORMED", "zero message ID"));
        }
        if self.decision.is_granted() {
            if self.durable_generation == 0 || self.envelope_bytes.is_empty() {
                return Err(err(
                    "WITNESS_RESPONSE_MALFORMED",
                    "grant lacks durable generation or envelope",
                ));
            }
        } else if self.durable_generation != 0 || !self.envelope_bytes.is_empty() {
            return Err(err(
                "WITNESS_RESPONSE_MALFORMED",
                "refusal carries authority material",
            ));
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate_shape()?;
        let mut writer = Writer::new();
        writer.bytes(WITNESS_RESPONSE_MAGIC);
        writer.u16(PROTOCOL_VERSION);
        writer.bytes(&self.message_id);
        writer.bytes(&self.request_digest);
        writer.id(&self.witness_id)?;
        writer.id(&self.key_id)?;
        writer.u16(self.decision.tag());
        writer.u64(self.durable_generation);
        writer.length_bytes(&self.envelope_bytes)?;
        writer.finish()
    }
}

pub(crate) fn witness_request_digest(bytes: &[u8]) -> Result<[u8; 32], ClusterError> {
    enforce_size(bytes)?;
    let mut digest = Sha256::new();
    digest.update(WITNESS_REQUEST_DIGEST_DOMAIN);
    digest.update(bytes);
    Ok(digest.finalize().into())
}

pub(crate) fn record_checksum(record: &[u8]) -> Result<u32, ClusterError> {
    let offset = record
        .len()
        .checked_sub(4)
        .ok_or_else(|| err("WAL_RECORD_INVALID", "record is shorter than checksum"))?;
    let checksum: [u8; 4] = record
        .get(offset..)
        .ok_or_else(|| err("WAL_RECORD_INVALID", "checksum missing"))?
        .try_into()
        .map_err(|_| err("WAL_RECORD_INVALID", "checksum length invalid"))?;
    Ok(u32::from_be_bytes(checksum))
}

pub(crate) fn first_record_state_root(record: &[u8]) -> [u8; 32] {
    let mut initial = Sha256::new();
    initial.update(RPO0_STATE_DOMAIN);
    initial.update(b"empty");
    let initial: [u8; 32] = initial.finalize().into();
    let mut next = Sha256::new();
    next.update(RPO0_STATE_DOMAIN);
    next.update(initial);
    next.update(record);
    next.finalize().into()
}

pub(crate) fn id(value: &str) -> Result<CanonicalId, ClusterError> {
    CanonicalId::new(value).map_err(|error| err("IDENTIFIER_INVALID", format!("{value}: {error}")))
}

fn domain_preimage(domain: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(domain.len().saturating_add(bytes.len()));
    output.extend_from_slice(domain);
    output.extend_from_slice(bytes);
    output
}

fn enforce_size(bytes: &[u8]) -> Result<(), ClusterError> {
    if bytes.is_empty() || bytes.len() > MAX_CLUSTER_FRAME {
        return Err(err(
            "PROTOCOL_SIZE_REFUSED",
            format!("frame length {} is outside bounds", bytes.len()),
        ));
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

    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(value.to_be_bytes().as_slice());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(value.to_be_bytes().as_slice());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(value.to_be_bytes().as_slice());
    }

    fn id(&mut self, value: &CanonicalId) -> Result<(), ClusterError> {
        let length = u16::try_from(value.as_str().len())
            .map_err(|_| err("PROTOCOL_LENGTH_OVERFLOW", "identifier too long"))?;
        self.u16(length);
        self.bytes(value.as_str().as_bytes());
        Ok(())
    }

    fn length_bytes(&mut self, value: &[u8]) -> Result<(), ClusterError> {
        let length = u32::try_from(value.len())
            .map_err(|_| err("PROTOCOL_LENGTH_OVERFLOW", "payload too long"))?;
        self.u32(length);
        self.bytes(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, ClusterError> {
        enforce_size(&self.bytes)?;
        Ok(self.bytes)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ClusterError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| err("PROTOCOL_LENGTH_OVERFLOW", "offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| err("PROTOCOL_TRUNCATED", "frame ended early"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ClusterError> {
        self.take(N)?
            .try_into()
            .map_err(|_| err("PROTOCOL_TRUNCATED", "fixed field ended early"))
    }

    fn u16(&mut self) -> Result<u16, ClusterError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, ClusterError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, ClusterError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }

    fn id(&mut self) -> Result<CanonicalId, ClusterError> {
        let length = usize::from(self.u16()?);
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|error| err("PROTOCOL_IDENTIFIER_INVALID", error.to_string()))?;
        id(value)
    }

    fn length_bytes(&mut self) -> Result<&'a [u8], ClusterError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| err("PROTOCOL_LENGTH_OVERFLOW", "payload length overflow"))?;
        if length > MAX_CLUSTER_FRAME {
            return Err(err("PROTOCOL_SIZE_REFUSED", "embedded payload too large"));
        }
        self.take(length)
    }

    fn expect_magic(&mut self, magic: &[u8; 8]) -> Result<(), ClusterError> {
        if self.take(magic.len())? != magic {
            return Err(err("PROTOCOL_MAGIC_REFUSED", "invalid frame magic"));
        }
        Ok(())
    }

    fn expect_version(&mut self) -> Result<(), ClusterError> {
        let version = self.u16()?;
        if version != PROTOCOL_VERSION {
            return Err(err(
                "PROTOCOL_VERSION_REFUSED",
                format!("unsupported version {version}"),
            ));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), ClusterError> {
        if self.offset != self.bytes.len() {
            return Err(err("PROTOCOL_TRAILING_BYTES", "unknown trailing fields"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn entry() -> WalEntry {
        WalEntry {
            commit_index: 1,
            operation_id: OperationId::new([9; 16]),
            previous_value: 0,
            increment: 1,
            value: 1,
        }
    }

    #[test]
    fn peer_request_round_trip_and_digest_are_deterministic() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let wal = entry();
        let request = PeerRequest::sign(wal.clone(), wal.encode(), &key).expect("sign request");
        let bytes = request.to_bytes().expect("encode request");
        let decoded = PeerRequest::from_bytes(&bytes).expect("decode request");
        decoded
            .verify(&key.verifying_key())
            .expect("verify request");
        assert_eq!(decoded, request);
        assert_eq!(
            decoded.digest().expect("digest"),
            request.digest().expect("digest")
        );
    }

    #[test]
    fn peer_response_is_bound_to_exact_request_digest() {
        let candidate = SigningKey::from_bytes(&[11; 32]);
        let peer = SigningKey::from_bytes(&[17; 32]);
        let wal = entry();
        let request =
            PeerRequest::sign(wal.clone(), wal.encode(), &candidate).expect("sign request");
        let response = PeerResponse::sign(
            &request,
            PeerDecision::Durable,
            1,
            record_checksum(&wal.encode()).expect("checksum"),
            &peer,
        )
        .expect("sign response");
        response
            .verify(&request, &peer.verifying_key())
            .expect("verify response");

        let other_entry = WalEntry {
            increment: 2,
            value: 2,
            ..wal
        };
        let other = PeerRequest::sign(other_entry.clone(), other_entry.encode(), &candidate)
            .expect("sign other request");
        let error = response
            .verify(&other, &peer.verifying_key())
            .expect_err("cross-request response must fail");
        assert_eq!(error.reason_code(), "PEER_RESPONSE_BINDING_REFUSED");
    }

    #[test]
    fn strict_decoder_rejects_trailing_field() {
        let key = SigningKey::from_bytes(&[11; 32]);
        let wal = entry();
        let request = PeerRequest::sign(wal.clone(), wal.encode(), &key).expect("sign request");
        let mut bytes = request.to_bytes().expect("encode request");
        bytes.push(1);
        let error = PeerRequest::from_bytes(&bytes).expect_err("trailing byte must fail");
        assert_eq!(error.reason_code(), "PROTOCOL_TRAILING_BYTES");
    }

    #[test]
    fn witness_response_rejects_cross_request_digest_and_tamper() {
        let witness = SigningKey::from_bytes(&[29; 32]);
        let first_digest = witness_request_digest(b"first-request").expect("first digest");
        let second_digest = witness_request_digest(b"second-request").expect("second digest");
        let response = WitnessResponse::sign(
            MessageId::new(LAB_MESSAGE_ID),
            first_digest,
            WitnessDecision::DurableGrant,
            1,
            vec![1, 2, 3],
            &witness,
        )
        .expect("sign witness response");
        response
            .verify(
                &MessageId::new(LAB_MESSAGE_ID),
                &first_digest,
                &witness.verifying_key(),
            )
            .expect("verify exact response");
        let error = response
            .verify(
                &MessageId::new(LAB_MESSAGE_ID),
                &second_digest,
                &witness.verifying_key(),
            )
            .expect_err("cross-request response must fail");
        assert_eq!(error.reason_code(), "WITNESS_RESPONSE_BINDING_REFUSED");

        let mut bytes = response.to_bytes().expect("encode response");
        let last = bytes.len().saturating_sub(1);
        if let Some(byte) = bytes.get_mut(last) {
            *byte ^= 0x80;
        }
        let tampered = WitnessResponse::from_bytes(&bytes).expect("shape still parses");
        let error = tampered
            .verify(
                &MessageId::new(LAB_MESSAGE_ID),
                &first_digest,
                &witness.verifying_key(),
            )
            .expect_err("tampered response must fail");
        assert_eq!(error.reason_code(), "WITNESS_RESPONSE_AUTH_REFUSED");
    }
}
