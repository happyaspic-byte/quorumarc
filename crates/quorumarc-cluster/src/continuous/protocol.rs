use ed25519_dalek::{Signature, Signer};
use quorumarc_rpo0::{
    CounterOperation, OperationId, RecoveredCounter, StateRoot, WalEntry, recover_wal,
};
use quorumarc_wire::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{ClusterError, err};

const VERSION: u16 = 1;
const CLIENT_REQUEST_MAGIC: &[u8; 8] = b"QACARQ\0\0";
const CLIENT_RESPONSE_MAGIC: &[u8; 8] = b"QACARS\0\0";
const REPLICA_REQUEST_MAGIC: &[u8; 8] = b"QACRRQ\0\0";
const REPLICA_RESPONSE_MAGIC: &[u8; 8] = b"QACRRS\0\0";
const CLIENT_REQUEST_DOMAIN: &[u8] = b"quorumarc/continuous/client-request/ed25519/v1\0";
const CLIENT_RESPONSE_DOMAIN: &[u8] = b"quorumarc/continuous/client-response/ed25519/v1\0";
const REPLICA_REQUEST_DOMAIN: &[u8] = b"quorumarc/continuous/replica-request/ed25519/v1\0";
const REPLICA_RESPONSE_DOMAIN: &[u8] = b"quorumarc/continuous/replica-response/ed25519/v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"quorumarc/continuous/request/sha256/v1\0";
pub(super) const MAX_CONTINUOUS_FRAME: usize = 131_072;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ClientDecision {
    Acknowledged,
    Refused,
    Unknown,
}

impl ClientDecision {
    const fn tag(self) -> u16 {
        match self {
            Self::Acknowledged => 1,
            Self::Refused => 100,
            Self::Unknown => 101,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Acknowledged),
            100 => Ok(Self::Refused),
            101 => Ok(Self::Unknown),
            _ => Err(err(
                "CONTINUOUS_RESPONSE_MALFORMED",
                "unknown client decision",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClientRequest {
    pub request_id: [u8; 16],
    pub policy_hash: [u8; 32],
    pub operation: CounterOperation,
    signature: [u8; 64],
}

impl ClientRequest {
    pub fn sign(
        request_id: [u8; 16],
        policy_hash: [u8; 32],
        operation: CounterOperation,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut request = Self {
            request_id,
            policy_hash,
            operation,
            signature: [0; 64],
        };
        request.validate()?;
        request.signature = key
            .sign(&domain(CLIENT_REQUEST_DOMAIN, &request.unsigned_bytes()?))
            .to_bytes();
        Ok(request)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(CLIENT_REQUEST_MAGIC)?;
        reader.expect_version()?;
        let request = Self {
            request_id: reader.array()?,
            policy_hash: reader.array()?,
            operation: CounterOperation {
                id: OperationId::new(reader.array()?),
                expected_commit_index: reader.u64()?,
                increment: reader.u64()?,
            },
            signature: reader.array()?,
        };
        reader.finish()?;
        request.validate()?;
        Ok(request)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ClusterError> {
        key.verify_strict(
            &domain(CLIENT_REQUEST_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "CONTINUOUS_REQUEST_AUTH_REFUSED",
                "invalid client signature",
            )
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], ClusterError> {
        Ok(request_digest(&self.to_bytes()?))
    }

    fn validate(&self) -> Result<(), ClusterError> {
        if self.request_id.iter().all(|byte| *byte == 0)
            || self.policy_hash.iter().all(|byte| *byte == 0)
            || self.operation.id.into_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(err(
                "CONTINUOUS_REQUEST_MALFORMED",
                "client request contains a zero sentinel",
            ));
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.bytes(CLIENT_REQUEST_MAGIC);
        writer.u16(VERSION);
        writer.bytes(&self.request_id);
        writer.bytes(&self.policy_hash);
        writer.bytes(&self.operation.id.into_bytes());
        writer.u64(self.operation.expected_commit_index);
        writer.u64(self.operation.increment);
        writer.finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ClientResponse {
    pub request_digest: [u8; 32],
    pub decision: ClientDecision,
    pub operation_id: OperationId,
    pub commit_index: u64,
    pub value: u64,
    pub state_root: StateRoot,
    pub left_role: u8,
    pub right_role: u8,
    pub left_checksum: u32,
    pub right_checksum: u32,
    signature: [u8; 64],
}

impl ClientResponse {
    pub fn sign(
        request: &ClientRequest,
        decision: ClientDecision,
        commit_index: u64,
        value: u64,
        state_root: StateRoot,
        checksums: [u32; 2],
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut response = Self {
            request_digest: request.digest()?,
            decision,
            operation_id: request.operation.id,
            commit_index,
            value,
            state_root,
            left_role: if decision == ClientDecision::Acknowledged {
                1
            } else {
                0
            },
            right_role: if decision == ClientDecision::Acknowledged {
                2
            } else {
                0
            },
            left_checksum: checksums[0],
            right_checksum: checksums[1],
            signature: [0; 64],
        };
        response.validate()?;
        response.signature = key
            .sign(&domain(CLIENT_RESPONSE_DOMAIN, &response.unsigned_bytes()?))
            .to_bytes();
        Ok(response)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(CLIENT_RESPONSE_MAGIC)?;
        reader.expect_version()?;
        let response = Self {
            request_digest: reader.array()?,
            decision: ClientDecision::from_tag(reader.u16()?)?,
            operation_id: OperationId::new(reader.array()?),
            commit_index: reader.u64()?,
            value: reader.u64()?,
            state_root: reader.array()?,
            left_role: reader.u8()?,
            right_role: reader.u8()?,
            left_checksum: reader.u32()?,
            right_checksum: reader.u32()?,
            signature: reader.array()?,
        };
        reader.finish()?;
        response.validate()?;
        Ok(response)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub fn verify(&self, request: &ClientRequest, key: &VerifyingKey) -> Result<(), ClusterError> {
        if self.request_digest != request.digest()? || self.operation_id != request.operation.id {
            return Err(err(
                "CONTINUOUS_RESPONSE_BINDING_REFUSED",
                "response does not bind exact client request",
            ));
        }
        key.verify_strict(
            &domain(CLIENT_RESPONSE_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "CONTINUOUS_RESPONSE_AUTH_REFUSED",
                "invalid primary signature",
            )
        })
    }

    fn validate(&self) -> Result<(), ClusterError> {
        if self.request_digest.iter().all(|byte| *byte == 0)
            || self.operation_id.into_bytes().iter().all(|byte| *byte == 0)
            || self.state_root.iter().all(|byte| *byte == 0)
            || (self.decision == ClientDecision::Acknowledged
                && (self.left_role != 1 || self.right_role != 2))
            || (self.decision != ClientDecision::Acknowledged
                && (self.left_role != 0
                    || self.right_role != 0
                    || self.left_checksum != 0
                    || self.right_checksum != 0))
        {
            return Err(err(
                "CONTINUOUS_RESPONSE_MALFORMED",
                "response contains a zero sentinel",
            ));
        }
        Ok(())
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.bytes(CLIENT_RESPONSE_MAGIC);
        writer.u16(VERSION);
        writer.bytes(&self.request_digest);
        writer.u16(self.decision.tag());
        writer.bytes(&self.operation_id.into_bytes());
        writer.u64(self.commit_index);
        writer.u64(self.value);
        writer.bytes(&self.state_root);
        writer.u8(self.left_role);
        writer.u8(self.right_role);
        writer.u32(self.left_checksum);
        writer.u32(self.right_checksum);
        writer.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplicaKind {
    Query,
    Append,
}

impl ReplicaKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Query => 1,
            Self::Append => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Query),
            2 => Ok(Self::Append),
            _ => Err(err(
                "CONTINUOUS_REPLICA_REQUEST_MALFORMED",
                "unknown replica request kind",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReplicaRequest {
    pub request_id: [u8; 16],
    pub kind: ReplicaKind,
    pub policy_hash: [u8; 32],
    pub entry: Option<WalEntry>,
    pub canonical_record: Vec<u8>,
    signature: [u8; 64],
}

impl ReplicaRequest {
    pub fn query(
        request_id: [u8; 16],
        policy_hash: [u8; 32],
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        Self::sign(
            request_id,
            ReplicaKind::Query,
            policy_hash,
            None,
            Vec::new(),
            key,
        )
    }

    pub fn append(
        request_id: [u8; 16],
        policy_hash: [u8; 32],
        entry: WalEntry,
        canonical_record: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        Self::sign(
            request_id,
            ReplicaKind::Append,
            policy_hash,
            Some(entry),
            canonical_record,
            key,
        )
    }

    fn sign(
        request_id: [u8; 16],
        kind: ReplicaKind,
        policy_hash: [u8; 32],
        entry: Option<WalEntry>,
        canonical_record: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut request = Self {
            request_id,
            kind,
            policy_hash,
            entry,
            canonical_record,
            signature: [0; 64],
        };
        request.validate()?;
        request.signature = key
            .sign(&domain(REPLICA_REQUEST_DOMAIN, &request.unsigned_bytes()?))
            .to_bytes();
        Ok(request)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(REPLICA_REQUEST_MAGIC)?;
        reader.expect_version()?;
        let request_id = reader.array()?;
        let kind = ReplicaKind::from_tag(reader.u8()?)?;
        let policy_hash = reader.array()?;
        let entry = WalEntry {
            commit_index: reader.u64()?,
            operation_id: OperationId::new(reader.array()?),
            previous_value: reader.u64()?,
            increment: reader.u64()?,
            value: reader.u64()?,
        };
        let canonical_record = reader.length_bytes()?.to_vec();
        let signature = reader.array()?;
        reader.finish()?;
        if kind == ReplicaKind::Query
            && (entry.commit_index != 0
                || entry.operation_id.into_bytes() != [0; 16]
                || entry.previous_value != 0
                || entry.increment != 0
                || entry.value != 0)
        {
            return Err(err(
                "CONTINUOUS_REPLICA_REQUEST_MALFORMED",
                "query carries noncanonical unused WAL fields",
            ));
        }
        let request = Self {
            request_id,
            kind,
            policy_hash,
            entry: match kind {
                ReplicaKind::Query => None,
                ReplicaKind::Append => Some(entry),
            },
            canonical_record,
            signature,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ClusterError> {
        key.verify_strict(
            &domain(REPLICA_REQUEST_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "CONTINUOUS_REPLICA_REQUEST_AUTH_REFUSED",
                "invalid primary signature",
            )
        })
    }

    pub fn digest(&self) -> Result<[u8; 32], ClusterError> {
        Ok(request_digest(&self.to_bytes()?))
    }

    fn validate(&self) -> Result<(), ClusterError> {
        if self.request_id.iter().all(|byte| *byte == 0)
            || self.policy_hash.iter().all(|byte| *byte == 0)
        {
            return Err(err(
                "CONTINUOUS_REPLICA_REQUEST_MALFORMED",
                "replica request contains a zero sentinel",
            ));
        }
        match (
            self.kind,
            self.entry.as_ref(),
            self.canonical_record.is_empty(),
        ) {
            (ReplicaKind::Query, None, true) => Ok(()),
            (ReplicaKind::Append, Some(entry), false)
                if entry.encode() == self.canonical_record =>
            {
                Ok(())
            }
            _ => Err(err(
                "CONTINUOUS_REPLICA_REQUEST_MALFORMED",
                "replica request fields are inconsistent",
            )),
        }
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.bytes(REPLICA_REQUEST_MAGIC);
        writer.u16(VERSION);
        writer.bytes(&self.request_id);
        writer.u8(self.kind.tag());
        writer.bytes(&self.policy_hash);
        let entry = self.entry.clone().unwrap_or(WalEntry {
            commit_index: 0,
            operation_id: OperationId::new([0; 16]),
            previous_value: 0,
            increment: 0,
            value: 0,
        });
        writer.u64(entry.commit_index);
        writer.bytes(&entry.operation_id.into_bytes());
        writer.u64(entry.previous_value);
        writer.u64(entry.increment);
        writer.u64(entry.value);
        writer.length_bytes(&self.canonical_record)?;
        writer.finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReplicaDecision {
    Progress,
    Durable,
    Refused,
}

impl ReplicaDecision {
    const fn tag(self) -> u16 {
        match self {
            Self::Progress => 1,
            Self::Durable => 2,
            Self::Refused => 100,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ClusterError> {
        match tag {
            1 => Ok(Self::Progress),
            2 => Ok(Self::Durable),
            100 => Ok(Self::Refused),
            _ => Err(err(
                "CONTINUOUS_REPLICA_RESPONSE_MALFORMED",
                "unknown replica decision",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ReplicaResponse {
    pub request_digest: [u8; 32],
    pub decision: ReplicaDecision,
    pub commit_index: u64,
    pub value: u64,
    pub state_root: StateRoot,
    pub record_checksum: u32,
    pub wal_bytes: Vec<u8>,
    signature: [u8; 64],
}

struct ReplicaResponseBody {
    decision: ReplicaDecision,
    commit_index: u64,
    value: u64,
    state_root: StateRoot,
    record_checksum: u32,
    wal_bytes: Vec<u8>,
}

impl ReplicaResponse {
    pub fn progress(
        request: &ReplicaRequest,
        wal_bytes: Vec<u8>,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let recovered = recover_wal(&wal_bytes)
            .map_err(|error| err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string()))?;
        Self::sign(
            request,
            ReplicaResponseBody {
                decision: ReplicaDecision::Progress,
                commit_index: recovered.commit_index,
                value: recovered.value,
                state_root: recovered.state_root,
                record_checksum: 0,
                wal_bytes,
            },
            key,
        )
    }

    pub fn durable(
        request: &ReplicaRequest,
        commit_index: u64,
        value: u64,
        state_root: StateRoot,
        checksum: u32,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        Self::sign(
            request,
            ReplicaResponseBody {
                decision: ReplicaDecision::Durable,
                commit_index,
                value,
                state_root,
                record_checksum: checksum,
                wal_bytes: Vec::new(),
            },
            key,
        )
    }

    fn sign(
        request: &ReplicaRequest,
        body: ReplicaResponseBody,
        key: &SigningKey,
    ) -> Result<Self, ClusterError> {
        let mut response = Self {
            request_digest: request.digest()?,
            decision: body.decision,
            commit_index: body.commit_index,
            value: body.value,
            state_root: body.state_root,
            record_checksum: body.record_checksum,
            wal_bytes: body.wal_bytes,
            signature: [0; 64],
        };
        response.validate()?;
        response.signature = key
            .sign(&domain(
                REPLICA_RESPONSE_DOMAIN,
                &response.unsigned_bytes()?,
            ))
            .to_bytes();
        Ok(response)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ClusterError> {
        let mut reader = Reader::new(bytes);
        reader.expect_magic(REPLICA_RESPONSE_MAGIC)?;
        reader.expect_version()?;
        let response = Self {
            request_digest: reader.array()?,
            decision: ReplicaDecision::from_tag(reader.u16()?)?,
            commit_index: reader.u64()?,
            value: reader.u64()?,
            state_root: reader.array()?,
            record_checksum: reader.u32()?,
            wal_bytes: reader.length_bytes()?.to_vec(),
            signature: reader.array()?,
        };
        reader.finish()?;
        response.validate()?;
        Ok(response)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        enforce_size(&bytes)?;
        Ok(bytes)
    }

    pub fn verify(&self, request: &ReplicaRequest, key: &VerifyingKey) -> Result<(), ClusterError> {
        if self.request_digest != request.digest()? {
            return Err(err(
                "CONTINUOUS_REPLICA_RESPONSE_BINDING_REFUSED",
                "response does not bind exact replica request",
            ));
        }
        key.verify_strict(
            &domain(REPLICA_RESPONSE_DOMAIN, &self.unsigned_bytes()?),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| {
            err(
                "CONTINUOUS_REPLICA_RESPONSE_AUTH_REFUSED",
                "invalid replica signature",
            )
        })
    }

    pub fn recovered(&self) -> Result<RecoveredCounter, ClusterError> {
        recover_wal(&self.wal_bytes)
            .map_err(|error| err("CONTINUOUS_REPLICA_WAL_REFUSED", error.to_string()))
    }

    fn validate(&self) -> Result<(), ClusterError> {
        if self.request_digest.iter().all(|byte| *byte == 0)
            || self.state_root.iter().all(|byte| *byte == 0)
        {
            return Err(err(
                "CONTINUOUS_REPLICA_RESPONSE_MALFORMED",
                "replica response contains a zero sentinel",
            ));
        }
        match self.decision {
            ReplicaDecision::Progress if self.record_checksum == 0 => Ok(()),
            ReplicaDecision::Durable if self.commit_index > 0 && self.wal_bytes.is_empty() => {
                Ok(())
            }
            ReplicaDecision::Refused
                if self.commit_index == 0
                    && self.record_checksum == 0
                    && self.wal_bytes.is_empty() =>
            {
                Ok(())
            }
            _ => Err(err(
                "CONTINUOUS_REPLICA_RESPONSE_MALFORMED",
                "replica response fields are inconsistent",
            )),
        }
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, ClusterError> {
        self.validate()?;
        let mut writer = Writer::new();
        writer.bytes(REPLICA_RESPONSE_MAGIC);
        writer.u16(VERSION);
        writer.bytes(&self.request_digest);
        writer.u16(self.decision.tag());
        writer.u64(self.commit_index);
        writer.u64(self.value);
        writer.bytes(&self.state_root);
        writer.u32(self.record_checksum);
        writer.length_bytes(&self.wal_bytes)?;
        writer.finish()
    }
}

fn request_digest(bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REQUEST_DIGEST_DOMAIN);
    digest.update(bytes);
    digest.finalize().into()
}

fn domain(prefix: &[u8], bytes: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(prefix.len().saturating_add(bytes.len()));
    value.extend_from_slice(prefix);
    value.extend_from_slice(bytes);
    value
}

fn enforce_size(bytes: &[u8]) -> Result<(), ClusterError> {
    if bytes.is_empty() || bytes.len() > MAX_CONTINUOUS_FRAME {
        return Err(err(
            "CONTINUOUS_PROTOCOL_SIZE_REFUSED",
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

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn length_bytes(&mut self, value: &[u8]) -> Result<(), ClusterError> {
        let length = u32::try_from(value.len())
            .map_err(|_| err("CONTINUOUS_PROTOCOL_LENGTH_OVERFLOW", "payload too long"))?;
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
            .ok_or_else(|| err("CONTINUOUS_PROTOCOL_LENGTH_OVERFLOW", "offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| err("CONTINUOUS_PROTOCOL_TRUNCATED", "frame ended early"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ClusterError> {
        self.take(N)?
            .try_into()
            .map_err(|_| err("CONTINUOUS_PROTOCOL_TRUNCATED", "fixed field ended early"))
    }

    fn u8(&mut self) -> Result<u8, ClusterError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ClusterError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ClusterError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ClusterError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn length_bytes(&mut self) -> Result<&'a [u8], ClusterError> {
        let length = usize::try_from(self.u32()?).map_err(|_| {
            err(
                "CONTINUOUS_PROTOCOL_LENGTH_OVERFLOW",
                "payload length overflow",
            )
        })?;
        if length > MAX_CONTINUOUS_FRAME {
            return Err(err(
                "CONTINUOUS_PROTOCOL_SIZE_REFUSED",
                "embedded payload too large",
            ));
        }
        self.take(length)
    }

    fn expect_magic(&mut self, magic: &[u8; 8]) -> Result<(), ClusterError> {
        if self.take(magic.len())? != magic {
            return Err(err(
                "CONTINUOUS_PROTOCOL_MAGIC_REFUSED",
                "invalid frame magic",
            ));
        }
        Ok(())
    }

    fn expect_version(&mut self) -> Result<(), ClusterError> {
        let version = self.u16()?;
        if version != VERSION {
            return Err(err(
                "CONTINUOUS_PROTOCOL_VERSION_REFUSED",
                format!("unsupported version {version}"),
            ));
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), ClusterError> {
        if self.offset != self.bytes.len() {
            return Err(err(
                "CONTINUOUS_PROTOCOL_TRAILING_BYTES",
                "unknown trailing fields",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn operation(byte: u8, expected: u64, increment: u64) -> CounterOperation {
        CounterOperation {
            id: OperationId::new([byte; 16]),
            expected_commit_index: expected,
            increment,
        }
    }

    #[test]
    fn client_frames_round_trip_and_bind_exact_request() {
        let client = SigningKey::from_bytes(&[41; 32]);
        let primary = SigningKey::from_bytes(&[43; 32]);
        let request = ClientRequest::sign([51; 16], [5; 32], operation(73, 0, 3), &client)
            .expect("sign client request");
        let decoded = ClientRequest::from_bytes(&request.to_bytes().expect("encode request"))
            .expect("decode request");
        decoded
            .verify(&client.verifying_key())
            .expect("verify request");
        let response = ClientResponse::sign(
            &request,
            ClientDecision::Acknowledged,
            1,
            3,
            [9; 32],
            [17, 19],
            &primary,
        )
        .expect("sign client response");
        let decoded_response =
            ClientResponse::from_bytes(&response.to_bytes().expect("encode response"))
                .expect("decode response");
        decoded_response
            .verify(&request, &primary.verifying_key())
            .expect("verify exact response");
        let other = ClientRequest::sign([52; 16], [5; 32], operation(83, 0, 3), &client)
            .expect("sign other request");
        assert_eq!(
            decoded_response
                .verify(&other, &primary.verifying_key())
                .expect_err("cross-request response must fail")
                .reason_code(),
            "CONTINUOUS_RESPONSE_BINDING_REFUSED"
        );
    }

    #[test]
    fn replica_frames_round_trip_reject_tamper_and_trailing_bytes() {
        let primary = SigningKey::from_bytes(&[43; 32]);
        let replica = SigningKey::from_bytes(&[47; 32]);
        let query =
            ReplicaRequest::query([61; 16], [5; 32], &primary).expect("sign progress query");
        let bytes = query.to_bytes().expect("encode query");
        let decoded = ReplicaRequest::from_bytes(&bytes).expect("decode query");
        let mut noncanonical_query = bytes.clone();
        noncanonical_query[59] = 1;
        assert_eq!(
            ReplicaRequest::from_bytes(&noncanonical_query)
                .expect_err("query with nonzero unused WAL field must fail")
                .reason_code(),
            "CONTINUOUS_REPLICA_REQUEST_MALFORMED"
        );
        decoded
            .verify(&primary.verifying_key())
            .expect("verify query");
        let progress = ReplicaResponse::progress(&query, Vec::new(), &replica)
            .expect("sign progress response");
        let progress_bytes = progress.to_bytes().expect("encode progress");
        let progress_decoded =
            ReplicaResponse::from_bytes(&progress_bytes).expect("decode progress");
        progress_decoded
            .verify(&query, &replica.verifying_key())
            .expect("verify progress");

        let mut tampered = progress_bytes;
        let last = tampered.len().saturating_sub(1);
        if let Some(byte) = tampered.get_mut(last) {
            *byte ^= 0x80;
        }
        let tampered = ReplicaResponse::from_bytes(&tampered).expect("shape remains valid");
        assert_eq!(
            tampered
                .verify(&query, &replica.verifying_key())
                .expect_err("tampered response must fail")
                .reason_code(),
            "CONTINUOUS_REPLICA_RESPONSE_AUTH_REFUSED"
        );

        let mut trailing = bytes;
        trailing.push(1);
        assert_eq!(
            ReplicaRequest::from_bytes(&trailing)
                .expect_err("trailing request byte must fail")
                .reason_code(),
            "CONTINUOUS_PROTOCOL_TRAILING_BYTES"
        );
    }
}
