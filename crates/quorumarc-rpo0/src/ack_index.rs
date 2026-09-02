use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, OFlags, flock};

use crate::{AcknowledgedWrite, CounterOperation, DurableReceipt, OperationId};

const MAGIC: [u8; 4] = *b"QACK";
const VERSION: u8 = 2;
const MAX_REPLICA_ID: usize = 64;
const MAX_INDEX_BYTES: usize = 1_048_576;
const CHECKSUM_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AckIndexError {
    Io,
    Corrupt,
    ConflictingOperation,
    TooLarge,
    OwnerLockRefused,
    Poisoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableClientAck {
    expected_commit_index: u64,
    increment: u64,
    acknowledgement: AcknowledgedWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AckPreflight {
    Fresh,
    Exact(AcknowledgedWrite),
}

#[derive(Debug)]
pub struct DurableAckIndex {
    path: PathBuf,
    file: File,
    acknowledgements: BTreeMap<OperationId, DurableClientAck>,
    poisoned: bool,
}

impl DurableAckIndex {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AckIndexError> {
        let path = path.as_ref().to_path_buf();
        reject_symlink_components(&path)?;
        let existing = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                validate_metadata(&metadata)?;
                Some(metadata)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_error) => return Err(AckIndexError::Io),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .mode(0o600)
            .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32)
            .open(&path)
            .map_err(|_error| AckIndexError::Io)?;
        flock(&file, FlockOperation::NonBlockingLockExclusive)
            .map_err(|_error| AckIndexError::OwnerLockRefused)?;
        let metadata = file.metadata().map_err(|_error| AckIndexError::Io)?;
        validate_metadata(&metadata)?;
        if let Some(expected) = existing {
            if expected.dev() != metadata.dev() || expected.ino() != metadata.ino() {
                return Err(AckIndexError::Corrupt);
            }
        }
        let length = usize::try_from(metadata.len()).map_err(|_error| AckIndexError::TooLarge)?;
        if length > MAX_INDEX_BYTES {
            return Err(AckIndexError::TooLarge);
        }
        let mut bytes = Vec::with_capacity(length);
        file.read_to_end(&mut bytes)
            .map_err(|_error| AckIndexError::Io)?;
        let acknowledgements = decode_index(&bytes)?;
        Ok(Self {
            path,
            file,
            acknowledgements,
            poisoned: false,
        })
    }

    #[must_use]
    pub fn get(&self, operation_id: OperationId) -> Option<&AcknowledgedWrite> {
        self.acknowledgements
            .get(&operation_id)
            .map(|entry| &entry.acknowledgement)
    }

    pub fn preflight(&self, operation: CounterOperation) -> Result<AckPreflight, AckIndexError> {
        match self.acknowledgements.get(&operation.id) {
            Some(entry)
                if entry.expected_commit_index == operation.expected_commit_index
                    && entry.increment == operation.increment =>
            {
                Ok(AckPreflight::Exact(entry.acknowledgement.clone()))
            }
            Some(_) => Err(AckIndexError::ConflictingOperation),
            None => Ok(AckPreflight::Fresh),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.acknowledgements.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.acknowledgements.is_empty()
    }

    pub fn record(
        &mut self,
        operation: CounterOperation,
        acknowledgement: &AcknowledgedWrite,
    ) -> Result<(), AckIndexError> {
        if self.poisoned {
            return Err(AckIndexError::Poisoned);
        }
        validate_acknowledgement(acknowledgement)?;
        if operation.id != acknowledgement.operation_id {
            return Err(AckIndexError::ConflictingOperation);
        }
        if operation.increment == 0
            || operation
                .expected_commit_index
                .checked_add(1)
                .is_none_or(|expected| expected != acknowledgement.commit_index)
        {
            return Err(AckIndexError::Corrupt);
        }
        let entry = DurableClientAck {
            expected_commit_index: operation.expected_commit_index,
            increment: operation.increment,
            acknowledgement: acknowledgement.clone(),
        };
        if let Some(existing) = self.acknowledgements.get(&acknowledgement.operation_id) {
            if existing == &entry {
                if let Err(error) = self.sync_durable() {
                    self.poisoned = true;
                    return Err(error);
                }
                return Ok(());
            }
            return Err(AckIndexError::ConflictingOperation);
        }
        let encoded = encode_record(&entry)?;
        let current_len = usize::try_from(
            self.file
                .metadata()
                .map_err(|_error| AckIndexError::Io)?
                .len(),
        )
        .map_err(|_error| AckIndexError::TooLarge)?;
        if current_len
            .checked_add(encoded.len())
            .is_none_or(|next_len| next_len > MAX_INDEX_BYTES)
        {
            return Err(AckIndexError::TooLarge);
        }
        if self.file.write_all(&encoded).is_err() {
            self.poisoned = true;
            return Err(AckIndexError::Io);
        }
        if let Err(error) = self.sync_durable() {
            self.poisoned = true;
            return Err(error);
        }
        self.acknowledgements
            .insert(acknowledgement.operation_id, entry);
        Ok(())
    }

    fn sync_durable(&mut self) -> Result<(), AckIndexError> {
        self.file.sync_all().map_err(|_error| AckIndexError::Io)?;
        verify_path_identity(&self.path, &self.file)?;
        sync_parent_directory(&self.path)?;
        verify_path_identity(&self.path, &self.file)
    }
}

fn encode_record(entry: &DurableClientAck) -> Result<Vec<u8>, AckIndexError> {
    let acknowledgement = &entry.acknowledgement;
    validate_acknowledgement(acknowledgement)?;
    let left = encode_receipt(&acknowledgement.replica_receipts[0])?;
    let right = encode_receipt(&acknowledgement.replica_receipts[1])?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&acknowledgement.operation_id.into_bytes());
    payload.extend_from_slice(&entry.expected_commit_index.to_be_bytes());
    payload.extend_from_slice(&entry.increment.to_be_bytes());
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

fn validate_acknowledgement(acknowledgement: &AcknowledgedWrite) -> Result<(), AckIndexError> {
    let [left, right] = &acknowledgement.replica_receipts;
    if acknowledgement
        .operation_id
        .into_bytes()
        .iter()
        .all(|byte| *byte == 0)
        || acknowledgement.commit_index == 0
        || acknowledgement.state_root.iter().all(|byte| *byte == 0)
        || left.replica_id == right.replica_id
        || left.commit_index != acknowledgement.commit_index
        || right.commit_index != acknowledgement.commit_index
        || left.record_checksum != right.record_checksum
    {
        return Err(AckIndexError::Corrupt);
    }
    Ok(())
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

fn decode_index(bytes: &[u8]) -> Result<BTreeMap<OperationId, DurableClientAck>, AckIndexError> {
    let mut acknowledgements = BTreeMap::new();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let (acknowledgement, consumed) = decode_record(remaining)?;
        remaining = remaining.get(consumed..).ok_or(AckIndexError::Corrupt)?;
        let operation_id = acknowledgement.acknowledgement.operation_id;
        if let Some(existing) = acknowledgements.get(&operation_id) {
            if existing != &acknowledgement {
                return Err(AckIndexError::ConflictingOperation);
            }
            continue;
        }
        acknowledgements.insert(operation_id, acknowledgement);
    }
    Ok(acknowledgements)
}

fn decode_record(bytes: &[u8]) -> Result<(DurableClientAck, usize), AckIndexError> {
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

fn decode_payload(payload: &[u8]) -> Result<DurableClientAck, AckIndexError> {
    let mut reader = Reader {
        bytes: payload,
        offset: 0,
    };
    let operation_id = OperationId::new(reader.take_array()?);
    let expected_commit_index = u64::from_be_bytes(reader.take_array()?);
    let increment = u64::from_be_bytes(reader.take_array()?);
    let commit_index = u64::from_be_bytes(reader.take_array()?);
    let value = u64::from_be_bytes(reader.take_array()?);
    let state_root = reader.take_array()?;
    let left = decode_receipt(&mut reader)?;
    let right = decode_receipt(&mut reader)?;
    if reader.offset != reader.bytes.len() {
        return Err(AckIndexError::Corrupt);
    }
    let acknowledgement = AcknowledgedWrite {
        operation_id,
        commit_index,
        value,
        state_root,
        replica_receipts: [left, right],
    };
    validate_acknowledgement(&acknowledgement)?;
    if increment == 0
        || expected_commit_index
            .checked_add(1)
            .is_none_or(|expected| expected != acknowledgement.commit_index)
    {
        return Err(AckIndexError::Corrupt);
    }
    Ok(DurableClientAck {
        expected_commit_index,
        increment,
        acknowledgement,
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

fn validate_metadata(metadata: &std::fs::Metadata) -> Result<(), AckIndexError> {
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.permissions().mode() & 0o077 != 0 {
        return Err(AckIndexError::Corrupt);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), AckIndexError> {
    let mut current = PathBuf::new();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    for component in parent.components() {
        current.push(component);
        if current.as_os_str().is_empty() {
            continue;
        }
        let metadata = std::fs::symlink_metadata(&current).map_err(|_error| AckIndexError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(AckIndexError::Corrupt);
        }
    }
    Ok(())
}

fn verify_path_identity(path: &Path, file: &File) -> Result<(), AckIndexError> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|_error| AckIndexError::Io)?;
    let file_metadata = file.metadata().map_err(|_error| AckIndexError::Io)?;
    validate_metadata(&path_metadata)?;
    if path_metadata.dev() != file_metadata.dev() || path_metadata.ino() != file_metadata.ino() {
        return Err(AckIndexError::Corrupt);
    }
    Ok(())
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
