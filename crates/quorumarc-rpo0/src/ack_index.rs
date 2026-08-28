use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use rustix::fs::OFlags;

use crate::{AcknowledgedWrite, DurableReceipt, OperationId};

const MAGIC: [u8; 4] = *b"QACK";
const VERSION: u8 = 1;
const MAX_REPLICA_ID: usize = 64;
const MAX_INDEX_BYTES: usize = 1_048_576;
const CHECKSUM_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckIndexError {
    Io,
    Corrupt,
    ConflictingOperation,
    TooLarge,
}

#[derive(Debug)]
pub struct DurableAckIndex {
    path: PathBuf,
    acknowledgements: BTreeMap<OperationId, AcknowledgedWrite>,
}

impl DurableAckIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AckIndexError> {
        let path = path.as_ref().to_path_buf();
        if let Ok(metadata) = std::fs::symlink_metadata(&path) {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || std::os::unix::fs::PermissionsExt::mode(&metadata.permissions()) & 0o077 != 0
            {
                return Err(AckIndexError::Corrupt);
            }
        }
        let bytes = read_file_or_empty(&path)?;
        if bytes.len() > MAX_INDEX_BYTES {
            return Err(AckIndexError::TooLarge);
        }
        let acknowledgements = decode_index(&bytes)?;
        Ok(Self {
            path,
            acknowledgements,
        })
    }

    #[must_use]
    pub fn get(&self, operation_id: OperationId) -> Option<&AcknowledgedWrite> {
        self.acknowledgements.get(&operation_id)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.acknowledgements.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.acknowledgements.is_empty()
    }

    pub fn record(&mut self, acknowledgement: &AcknowledgedWrite) -> Result<(), AckIndexError> {
        if let Some(existing) = self.acknowledgements.get(&acknowledgement.operation_id) {
            if existing == acknowledgement {
                return Ok(());
            }
            return Err(AckIndexError::ConflictingOperation);
        }
        let encoded = encode_record(acknowledgement)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
            .map_err(|_error| AckIndexError::Io)?;
        let current_len =
            usize::try_from(file.metadata().map_err(|_error| AckIndexError::Io)?.len())
                .map_err(|_error| AckIndexError::TooLarge)?;
        if current_len
            .checked_add(encoded.len())
            .is_none_or(|next_len| next_len > MAX_INDEX_BYTES)
        {
            return Err(AckIndexError::TooLarge);
        }
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_error| AckIndexError::Io)?;
        sync_parent_directory(&self.path)?;
        self.acknowledgements
            .insert(acknowledgement.operation_id, acknowledgement.clone());
        Ok(())
    }
}

fn encode_record(acknowledgement: &AcknowledgedWrite) -> Result<Vec<u8>, AckIndexError> {
    let left = encode_receipt(&acknowledgement.replica_receipts[0])?;
    let right = encode_receipt(&acknowledgement.replica_receipts[1])?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&acknowledgement.operation_id.into_bytes());
    payload.extend_from_slice(&acknowledgement.commit_index.to_be_bytes());
    payload.extend_from_slice(&acknowledgement.value.to_be_bytes());
    payload.extend_from_slice(&acknowledgement.state_root);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    let payload_len = u16::try_from(payload.len()).map_err(|_error| AckIndexError::TooLarge)?;
    let mut record = Vec::with_capacity(MAGIC.len() + 1 + 2 + payload.len() + CHECKSUM_LEN);
    record.extend_from_slice(&MAGIC);
    record.push(VERSION);
    record.extend_from_slice(&payload_len.to_be_bytes());
    record.extend_from_slice(&payload);
    let checksum = crc32(&record);
    record.extend_from_slice(&checksum.to_be_bytes());
    Ok(record)
}

fn encode_receipt(receipt: &DurableReceipt) -> Result<Vec<u8>, AckIndexError> {
    let replica_id = receipt.replica_id.as_bytes();
    if replica_id.is_empty() || replica_id.len() > MAX_REPLICA_ID {
        return Err(AckIndexError::Corrupt);
    }
    let mut encoded = Vec::with_capacity(1 + replica_id.len() + 8 + 4);
    encoded.push(u8::try_from(replica_id.len()).map_err(|_error| AckIndexError::Corrupt)?);
    encoded.extend_from_slice(replica_id);
    encoded.extend_from_slice(&receipt.commit_index.to_be_bytes());
    encoded.extend_from_slice(&receipt.record_checksum.to_be_bytes());
    Ok(encoded)
}

fn decode_index(bytes: &[u8]) -> Result<BTreeMap<OperationId, AcknowledgedWrite>, AckIndexError> {
    let mut acknowledgements = BTreeMap::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let (acknowledgement, consumed) = decode_record(remaining)?;
        remaining = remaining.get(consumed..).ok_or(AckIndexError::Corrupt)?;
        if let Some(existing) = acknowledgements.get(&acknowledgement.operation_id) {
            if existing != &acknowledgement {
                return Err(AckIndexError::ConflictingOperation);
            }
            continue;
        }
        acknowledgements.insert(acknowledgement.operation_id, acknowledgement);
    }
    Ok(acknowledgements)
}

fn decode_record(bytes: &[u8]) -> Result<(AcknowledgedWrite, usize), AckIndexError> {
    if bytes.len() < MAGIC.len() + 1 + 2 + CHECKSUM_LEN {
        return Err(AckIndexError::Corrupt);
    }
    if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
        return Err(AckIndexError::Corrupt);
    }
    if bytes.get(MAGIC.len()).copied() != Some(VERSION) {
        return Err(AckIndexError::Corrupt);
    }
    let payload_len = u16::from_be_bytes([
        *bytes.get(MAGIC.len() + 1).ok_or(AckIndexError::Corrupt)?,
        *bytes.get(MAGIC.len() + 2).ok_or(AckIndexError::Corrupt)?,
    ]) as usize;
    let header_len = MAGIC.len() + 1 + 2;
    let record_len = header_len
        .checked_add(payload_len)
        .and_then(|len| len.checked_add(CHECKSUM_LEN))
        .ok_or(AckIndexError::Corrupt)?;
    let record = bytes.get(..record_len).ok_or(AckIndexError::Corrupt)?;
    let expected = crc32(&record[..record_len - CHECKSUM_LEN]);
    let actual = u32::from_be_bytes(
        record[record_len - CHECKSUM_LEN..]
            .try_into()
            .map_err(|_error| AckIndexError::Corrupt)?,
    );
    if expected != actual {
        return Err(AckIndexError::Corrupt);
    }
    let payload = &record[header_len..record_len - CHECKSUM_LEN];
    let acknowledgement = decode_payload(payload)?;
    Ok((acknowledgement, record_len))
}

fn decode_payload(payload: &[u8]) -> Result<AcknowledgedWrite, AckIndexError> {
    let mut reader = Reader {
        bytes: payload,
        offset: 0,
    };
    let operation_id = OperationId::new(reader.take_array()?);
    let commit_index = u64::from_be_bytes(reader.take_array()?);
    let value = u64::from_be_bytes(reader.take_array()?);
    let state_root = reader.take_array()?;
    let left = decode_receipt(&mut reader)?;
    let right = decode_receipt(&mut reader)?;
    if reader.offset != reader.bytes.len() {
        return Err(AckIndexError::Corrupt);
    }
    Ok(AcknowledgedWrite {
        operation_id,
        commit_index,
        value,
        state_root,
        replica_receipts: [left, right],
    })
}

fn decode_receipt(reader: &mut Reader<'_>) -> Result<DurableReceipt, AckIndexError> {
    let replica_len = usize::from(reader.take_u8()?);
    if replica_len == 0 || replica_len > MAX_REPLICA_ID {
        return Err(AckIndexError::Corrupt);
    }
    let replica_id = reader.take(replica_len)?;
    let replica_id =
        String::from_utf8(replica_id.to_vec()).map_err(|_error| AckIndexError::Corrupt)?;
    let commit_index = u64::from_be_bytes(reader.take_array()?);
    let record_checksum = u32::from_be_bytes(reader.take_array()?);
    Ok(DurableReceipt {
        replica_id,
        commit_index,
        record_checksum,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], AckIndexError> {
        let end = self.offset.checked_add(len).ok_or(AckIndexError::Corrupt)?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or(AckIndexError::Corrupt)?;
        self.offset = end;
        Ok(slice)
    }

    fn take_array<const N: usize>(&mut self) -> Result<[u8; N], AckIndexError> {
        self.take(N)?
            .try_into()
            .map_err(|_error| AckIndexError::Corrupt)
    }

    fn take_u8(&mut self) -> Result<u8, AckIndexError> {
        let value = *self.bytes.get(self.offset).ok_or(AckIndexError::Corrupt)?;
        self.offset = self.offset.checked_add(1).ok_or(AckIndexError::Corrupt)?;
        Ok(value)
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn read_file_or_empty(path: &Path) -> Result<Vec<u8>, AckIndexError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path);
    match file {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|_error| AckIndexError::Io)?;
            Ok(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_error) => Err(AckIndexError::Io),
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), AckIndexError> {
    let parent = match path.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_error| AckIndexError::Io)
}
