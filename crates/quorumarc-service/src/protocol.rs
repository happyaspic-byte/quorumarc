use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::management_journal::{
    JournalError, ManagementJournal, ManagementOperation, ManagementOutcome,
};

const MAGIC: &[u8; 8] = b"QARCPR02";
const VERSION: u16 = 2;
const SIGNATURE_LEN: usize = 64;
const MAX_ID_LEN: usize = 128;
const MAX_PAYLOAD_LEN: usize = 65_536;
const SIGNATURE_DOMAIN: &[u8] = b"quorumarc/production-rpc/ed25519/v2\0";
const VOTE_PAYLOAD_MAGIC: &[u8; 8] = b"QARCVP01";
const VOTE_PAYLOAD_LEN: usize = VOTE_PAYLOAD_MAGIC.len() + 32 + 8 + 8 + 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionFrameKind {
    Request,
    Response,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionRequest {
    pub cluster_id: String,
    pub workload_id: String,
    pub node_id: String,
    pub key_id: String,
    pub request_id: [u8; 16],
    pub sequence: u64,
    pub incarnation: u64,
    pub epoch: u64,
    pub progress_commit: u64,
    pub policy_hash: [u8; 32],
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionVotePayload {
    state_root: [u8; 32],
    required_commit: u64,
    lease_not_before_ms: u64,
    lease_expires_at_ms: u64,
}

impl ProductionVotePayload {
    pub fn new(
        state_root: [u8; 32],
        required_commit: u64,
        lease_not_before_ms: u64,
        lease_expires_at_ms: u64,
    ) -> Result<Self, ProductionFrameError> {
        if state_root.iter().all(|byte| *byte == 0) || lease_not_before_ms >= lease_expires_at_ms {
            return Err(ProductionFrameError::Malformed);
        }
        Ok(Self {
            state_root,
            required_commit,
            lease_not_before_ms,
            lease_expires_at_ms,
        })
    }

    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(VOTE_PAYLOAD_LEN);
        bytes.extend_from_slice(VOTE_PAYLOAD_MAGIC);
        bytes.extend_from_slice(&self.state_root);
        bytes.extend_from_slice(&self.required_commit.to_be_bytes());
        bytes.extend_from_slice(&self.lease_not_before_ms.to_be_bytes());
        bytes.extend_from_slice(&self.lease_expires_at_ms.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionFrameError> {
        if bytes.len() != VOTE_PAYLOAD_LEN
            || &bytes[..VOTE_PAYLOAD_MAGIC.len()] != VOTE_PAYLOAD_MAGIC
        {
            return Err(ProductionFrameError::Malformed);
        }
        let mut cursor = VOTE_PAYLOAD_MAGIC.len();
        Self::new(
            read_array(bytes, &mut cursor)?,
            read_u64(bytes, &mut cursor)?,
            read_u64(bytes, &mut cursor)?,
            read_u64(bytes, &mut cursor)?,
        )
    }

    #[must_use]
    pub const fn state_root(self) -> [u8; 32] {
        self.state_root
    }

    #[must_use]
    pub const fn required_commit(self) -> u64 {
        self.required_commit
    }

    #[must_use]
    pub const fn lease_not_before_ms(self) -> u64 {
        self.lease_not_before_ms
    }

    #[must_use]
    pub const fn lease_expires_at_ms(self) -> u64 {
        self.lease_expires_at_ms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionFrame {
    kind: ProductionFrameKind,
    request: ProductionRequest,
    signature: [u8; SIGNATURE_LEN],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionFrameError {
    Malformed,
    AuthenticationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionError {
    Malformed,
    AuthenticationFailed,
    ReplayRefused,
}

impl AdmissionError {
    #[must_use]
    pub const fn is_node_failure_suspicion(self) -> bool {
        false
    }
}

/// Verifies application signatures, then records exact request identity durably.
#[derive(Debug)]
pub struct AuthenticatedRequestJournal {
    journal: ManagementJournal,
    cluster_id: String,
    workload_id: String,
    node_id: String,
    key_id: String,
    verifying_key: VerifyingKey,
}

impl AuthenticatedRequestJournal {
    #[must_use]
    pub fn new(
        journal: ManagementJournal,
        cluster_id: impl Into<String>,
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Self {
        Self {
            journal,
            cluster_id: cluster_id.into(),
            workload_id: workload_id.into(),
            node_id: node_id.into(),
            key_id: key_id.into(),
            verifying_key,
        }
    }

    pub fn admit(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        let frame = ProductionFrame::decode(bytes).map_err(|error| match error {
            ProductionFrameError::Malformed => AdmissionError::Malformed,
            ProductionFrameError::AuthenticationFailed => AdmissionError::AuthenticationFailed,
        })?;
        if frame.kind() != ProductionFrameKind::Request {
            return Err(AdmissionError::Malformed);
        }
        frame
            .verify(&self.verifying_key)
            .map_err(|error| match error {
                ProductionFrameError::Malformed => AdmissionError::Malformed,
                ProductionFrameError::AuthenticationFailed => AdmissionError::AuthenticationFailed,
            })?;
        let request = frame.request();
        if request.cluster_id != self.cluster_id
            || request.workload_id != self.workload_id
            || request.node_id != self.node_id
            || request.key_id != self.key_id
        {
            return Err(AdmissionError::AuthenticationFailed);
        }
        let digest = request_digest(request);
        let operation = ManagementOperation::new(request.sequence, request.request_id, digest)
            .map_err(|_error| AdmissionError::Malformed)?;
        self.journal.record(operation).map_err(|error| match error {
            JournalError::ConflictingOperation | JournalError::StaleSequence => {
                AdmissionError::ReplayRefused
            }
            JournalError::InvalidOperation
            | JournalError::Corrupt
            | JournalError::IdentityMismatch => AdmissionError::Malformed,
            JournalError::Capacity | JournalError::Io => AdmissionError::ReplayRefused,
        })
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.journal.highest_sequence()
    }
}

fn request_digest(request: &ProductionRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SIGNATURE_DOMAIN);
    hasher.update(request.cluster_id.as_bytes());
    hasher.update([0]);
    hasher.update(request.workload_id.as_bytes());
    hasher.update([0]);
    hasher.update(request.node_id.as_bytes());
    hasher.update([0]);
    hasher.update(request.key_id.as_bytes());
    hasher.update([0]);
    hasher.update(request.request_id);
    hasher.update(request.sequence.to_be_bytes());
    hasher.update(request.incarnation.to_be_bytes());
    hasher.update(request.epoch.to_be_bytes());
    hasher.update(request.progress_commit.to_be_bytes());
    hasher.update(request.policy_hash);
    hasher.update((request.payload.len() as u32).to_be_bytes());
    hasher.update(&request.payload);
    hasher.finalize().into()
}

impl ProductionFrame {
    pub fn sign(
        kind: ProductionFrameKind,
        request: ProductionRequest,
        key: &SigningKey,
    ) -> Result<Self, ProductionFrameError> {
        validate_request(&request)?;
        let statement = encode_statement(kind, &request)?;
        let signature = key.sign(&signature_preimage(&statement)).to_bytes();
        Ok(Self {
            kind,
            request,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProductionFrameError> {
        validate_request(&self.request)?;
        let mut bytes = encode_statement(self.kind, &self.request)?;
        bytes.extend_from_slice(&self.signature);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionFrameError> {
        if bytes.len() < MAGIC.len() + 2 + 1 + SIGNATURE_LEN {
            return Err(ProductionFrameError::Malformed);
        }
        let statement_len = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(ProductionFrameError::Malformed)?;
        let statement = &bytes[..statement_len];
        let mut cursor = 0_usize;
        if take(statement, &mut cursor, MAGIC.len())? != MAGIC {
            return Err(ProductionFrameError::Malformed);
        }
        let version = read_u16(statement, &mut cursor)?;
        if version != VERSION {
            return Err(ProductionFrameError::Malformed);
        }
        let kind = match read_u8(statement, &mut cursor)? {
            1 => ProductionFrameKind::Request,
            2 => ProductionFrameKind::Response,
            _ => return Err(ProductionFrameError::Malformed),
        };
        let request = ProductionRequest {
            cluster_id: read_id(statement, &mut cursor)?,
            workload_id: read_id(statement, &mut cursor)?,
            node_id: read_id(statement, &mut cursor)?,
            key_id: read_id(statement, &mut cursor)?,
            request_id: read_array(statement, &mut cursor)?,
            sequence: read_u64(statement, &mut cursor)?,
            incarnation: read_u64(statement, &mut cursor)?,
            epoch: read_u64(statement, &mut cursor)?,
            progress_commit: read_u64(statement, &mut cursor)?,
            policy_hash: read_array(statement, &mut cursor)?,
            payload: read_payload(statement, &mut cursor)?,
        };
        if cursor != statement.len() {
            return Err(ProductionFrameError::Malformed);
        }
        validate_request(&request)?;
        let signature_bytes: [u8; SIGNATURE_LEN] = bytes[statement_len..]
            .try_into()
            .map_err(|_error| ProductionFrameError::Malformed)?;
        Ok(Self {
            kind,
            request,
            signature: signature_bytes,
        })
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), ProductionFrameError> {
        let statement = encode_statement(self.kind, &self.request)?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&signature_preimage(&statement), &signature)
            .map_err(|_error| ProductionFrameError::AuthenticationFailed)
    }

    #[must_use]
    pub const fn kind(&self) -> ProductionFrameKind {
        self.kind
    }

    #[must_use]
    pub const fn request(&self) -> &ProductionRequest {
        &self.request
    }
}

fn validate_request(request: &ProductionRequest) -> Result<(), ProductionFrameError> {
    for id in [
        &request.cluster_id,
        &request.workload_id,
        &request.node_id,
        &request.key_id,
    ] {
        if id.is_empty()
            || id.len() > MAX_ID_LEN
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ProductionFrameError::Malformed);
        }
    }
    if request.request_id.iter().all(|byte| *byte == 0)
        || request.sequence == 0
        || request.incarnation == 0
        || request.epoch == 0
        || request.policy_hash.iter().all(|byte| *byte == 0)
        || request.payload.len() > MAX_PAYLOAD_LEN
    {
        return Err(ProductionFrameError::Malformed);
    }
    Ok(())
}

fn encode_statement(
    kind: ProductionFrameKind,
    request: &ProductionRequest,
) -> Result<Vec<u8>, ProductionFrameError> {
    validate_request(request)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(match kind {
        ProductionFrameKind::Request => 1,
        ProductionFrameKind::Response => 2,
    });
    for id in [
        &request.cluster_id,
        &request.workload_id,
        &request.node_id,
        &request.key_id,
    ] {
        let len = u8::try_from(id.len()).map_err(|_error| ProductionFrameError::Malformed)?;
        bytes.push(len);
        bytes.extend_from_slice(id.as_bytes());
    }
    bytes.extend_from_slice(&request.request_id);
    bytes.extend_from_slice(&request.sequence.to_be_bytes());
    bytes.extend_from_slice(&request.incarnation.to_be_bytes());
    bytes.extend_from_slice(&request.epoch.to_be_bytes());
    bytes.extend_from_slice(&request.progress_commit.to_be_bytes());
    bytes.extend_from_slice(&request.policy_hash);
    let payload_len =
        u32::try_from(request.payload.len()).map_err(|_error| ProductionFrameError::Malformed)?;
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(&request.payload);
    Ok(bytes)
}

fn signature_preimage(statement: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + statement.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(statement);
    preimage
}

fn read_id(bytes: &[u8], cursor: &mut usize) -> Result<String, ProductionFrameError> {
    let len = usize::from(read_u8(bytes, cursor)?);
    if len == 0 || len > MAX_ID_LEN {
        return Err(ProductionFrameError::Malformed);
    }
    let value = take(bytes, cursor, len)?;
    String::from_utf8(value.to_vec()).map_err(|_error| ProductionFrameError::Malformed)
}

fn read_payload(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, ProductionFrameError> {
    let len = usize::try_from(read_u32(bytes, cursor)?)
        .map_err(|_error| ProductionFrameError::Malformed)?;
    if len > MAX_PAYLOAD_LEN {
        return Err(ProductionFrameError::Malformed);
    }
    Ok(take(bytes, cursor, len)?.to_vec())
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8, ProductionFrameError> {
    Ok(take(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16, ProductionFrameError> {
    Ok(u16::from_be_bytes(read_array(bytes, cursor)?))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, ProductionFrameError> {
    Ok(u32::from_be_bytes(read_array(bytes, cursor)?))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64, ProductionFrameError> {
    Ok(u64::from_be_bytes(read_array(bytes, cursor)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    cursor: &mut usize,
) -> Result<[u8; N], ProductionFrameError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_error| ProductionFrameError::Malformed)
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProductionFrameError> {
    let end = cursor
        .checked_add(len)
        .ok_or(ProductionFrameError::Malformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ProductionFrameError::Malformed)?;
    *cursor = end;
    Ok(value)
}
