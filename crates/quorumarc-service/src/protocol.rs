use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const MAGIC: &[u8; 8] = b"QARCPR02";
const VERSION: u16 = 2;
const SIGNATURE_LEN: usize = 64;
const MAX_ID_LEN: usize = 128;
const MAX_PAYLOAD_LEN: usize = 65_536;
const SIGNATURE_DOMAIN: &[u8] = b"quorumarc/production-rpc/ed25519/v2\0";

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
    pub incarnation: u64,
    pub epoch: u64,
    pub progress_commit: u64,
    pub policy_hash: [u8; 32],
    pub payload: Vec<u8>,
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
