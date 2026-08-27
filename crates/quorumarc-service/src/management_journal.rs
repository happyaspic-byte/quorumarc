use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, OFlags, flock};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"QARCMJ02";
const CHECKSUM_DOMAIN: &[u8] = b"quorumarc/management-journal/v2\0";
const IDENTITY_LEN: usize = 16;
const OPERATION_ID_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const CHECKSUM_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + IDENTITY_LEN;
const RECORD_BODY_LEN: usize = 8 + OPERATION_ID_LEN + DIGEST_LEN;
const RECORD_LEN: usize = RECORD_BODY_LEN + CHECKSUM_LEN;

/// Durable, restart-safe management anti-replay journal.
#[derive(Debug)]
pub struct ManagementJournal {
    path: PathBuf,
    identity: [u8; IDENTITY_LEN],
    operations: Vec<ManagementOperation>,
    _owner: File,
}

/// One signed management operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManagementOperation {
    sequence: u64,
    operation_id: [u8; OPERATION_ID_LEN],
    digest: [u8; DIGEST_LEN],
}

/// Whether a journal record wrote a new durable generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagementOutcome {
    Committed,
    AlreadyDurable,
}

/// Typed management-journal refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JournalError {
    IdentityMismatch,
    ConflictingOperation,
    StaleSequence,
    InvalidOperation,
    Capacity,
    OwnerLockRefused,
    Corrupt,
    Io,
}

impl ManagementOperation {
    /// Builds a strictly sequenced management operation.
    pub fn new(
        sequence: u64,
        operation_id: [u8; OPERATION_ID_LEN],
        digest: [u8; DIGEST_LEN],
    ) -> Result<Self, JournalError> {
        if sequence == 0 || operation_id.iter().all(|byte| *byte == 0) {
            return Err(JournalError::InvalidOperation);
        }
        Ok(Self {
            sequence,
            operation_id,
            digest,
        })
    }
}

impl ManagementJournal {
    /// Opens or creates an identity-bound append-only management journal.
    pub fn open(directory: &Path, identity: [u8; IDENTITY_LEN]) -> Result<Self, JournalError> {
        fs::create_dir_all(directory).map_err(|_error| JournalError::Io)?;
        let path = directory.join("management.journal");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(mut file) => {
                lock_owner(&file)?;
                file.write_all(&header(identity))
                    .and_then(|()| file.sync_all())
                    .map_err(|_error| JournalError::Io)?;
                File::open(directory)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|_error| JournalError::Io)?;
                Ok(Self {
                    path,
                    identity,
                    operations: Vec::new(),
                    _owner: file,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let owner = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                    .open(&path)
                    .map_err(|_error| match fs::symlink_metadata(&path) {
                        Ok(metadata) if metadata.file_type().is_symlink() => JournalError::Corrupt,
                        Ok(_) | Err(_) => JournalError::Io,
                    })?;
                lock_owner(&owner)?;
                let (recovered_identity, operations) = recover(&path)?;
                if recovered_identity != identity {
                    return Err(JournalError::IdentityMismatch);
                }
                Ok(Self {
                    path,
                    identity,
                    operations,
                    _owner: owner,
                })
            }
            Err(_error) => Err(JournalError::Io),
        }
    }

    /// Highest committed sequence.
    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.operations
            .last()
            .map_or(0, |operation| operation.sequence)
    }

    /// Records an exact-retry-safe management operation.
    pub fn record(
        &mut self,
        operation: ManagementOperation,
    ) -> Result<ManagementOutcome, JournalError> {
        if let Some(existing) = self
            .operations
            .iter()
            .find(|existing| existing.operation_id == operation.operation_id)
        {
            return if *existing == operation {
                Ok(ManagementOutcome::AlreadyDurable)
            } else {
                Err(JournalError::ConflictingOperation)
            };
        }
        if let Some(existing) = self
            .operations
            .iter()
            .find(|existing| existing.sequence == operation.sequence)
        {
            return if *existing == operation {
                Ok(ManagementOutcome::AlreadyDurable)
            } else {
                Err(JournalError::StaleSequence)
            };
        }
        let expected = self.highest_sequence().saturating_add(1);
        if operation.sequence != expected {
            return Err(JournalError::StaleSequence);
        }

        let next_size = HEADER_LEN
            .checked_add(
                self.operations
                    .len()
                    .saturating_add(1)
                    .saturating_mul(RECORD_LEN),
            )
            .ok_or(JournalError::Capacity)?;
        if u64::try_from(next_size).map_err(|_error| JournalError::Capacity)? > MAX_JOURNAL_SIZE {
            return Err(JournalError::Capacity);
        }

        let encoded = encode_record(self.identity, operation);
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
            .map_err(|_error| JournalError::Io)?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_error| JournalError::Io)?;
        self.operations.push(operation);
        Ok(ManagementOutcome::Committed)
    }
}

fn lock_owner(file: &File) -> Result<(), JournalError> {
    flock(file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_error| JournalError::OwnerLockRefused)
}

fn header(identity: [u8; IDENTITY_LEN]) -> [u8; HEADER_LEN] {
    let mut bytes = [0_u8; HEADER_LEN];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()..].copy_from_slice(&identity);
    bytes
}

const MAX_JOURNAL_SIZE: u64 = 1_048_576;

fn recover(path: &Path) -> Result<([u8; IDENTITY_LEN], Vec<ManagementOperation>), JournalError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_error| match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => JournalError::Corrupt,
            Ok(_) | Err(_) => JournalError::Io,
        })?;
    let metadata = file.metadata().map_err(|_error| JournalError::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_JOURNAL_SIZE
    {
        return Err(JournalError::Corrupt);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_JOURNAL_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| JournalError::Io)?;
    if bytes.len() > MAX_JOURNAL_SIZE as usize {
        return Err(JournalError::Corrupt);
    }
    if bytes.len() < HEADER_LEN
        || &bytes[..MAGIC.len()] != MAGIC
        || (bytes.len() - HEADER_LEN) % RECORD_LEN != 0
    {
        return Err(JournalError::Corrupt);
    }
    let mut identity = [0_u8; IDENTITY_LEN];
    identity.copy_from_slice(&bytes[MAGIC.len()..HEADER_LEN]);
    let mut operations = Vec::new();
    for record in bytes[HEADER_LEN..].chunks_exact(RECORD_LEN) {
        let operation = decode_record(identity, record)?;
        let expected = u64::try_from(operations.len())
            .map_err(|_error| JournalError::Corrupt)?
            .saturating_add(1);
        if operation.sequence != expected
            || operations.iter().any(|existing: &ManagementOperation| {
                existing.operation_id == operation.operation_id
            })
        {
            return Err(JournalError::Corrupt);
        }
        operations.push(operation);
    }
    Ok((identity, operations))
}

fn encode_record(identity: [u8; IDENTITY_LEN], operation: ManagementOperation) -> [u8; RECORD_LEN] {
    let mut bytes = [0_u8; RECORD_LEN];
    bytes[..8].copy_from_slice(&operation.sequence.to_be_bytes());
    bytes[8..8 + OPERATION_ID_LEN].copy_from_slice(&operation.operation_id);
    bytes[8 + OPERATION_ID_LEN..RECORD_BODY_LEN].copy_from_slice(&operation.digest);
    let checksum = record_checksum(identity, &bytes[..RECORD_BODY_LEN]);
    bytes[RECORD_BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn decode_record(
    identity: [u8; IDENTITY_LEN],
    bytes: &[u8],
) -> Result<ManagementOperation, JournalError> {
    let expected = record_checksum(identity, &bytes[..RECORD_BODY_LEN]);
    if bytes[RECORD_BODY_LEN..] != expected {
        return Err(JournalError::Corrupt);
    }
    let sequence = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_error| JournalError::Corrupt)?,
    );
    let mut operation_id = [0_u8; OPERATION_ID_LEN];
    operation_id.copy_from_slice(&bytes[8..8 + OPERATION_ID_LEN]);
    let mut digest = [0_u8; DIGEST_LEN];
    digest.copy_from_slice(&bytes[8 + OPERATION_ID_LEN..RECORD_BODY_LEN]);
    ManagementOperation::new(sequence, operation_id, digest)
}

fn record_checksum(identity: [u8; IDENTITY_LEN], body: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(identity);
    hasher.update(body);
    hasher.finalize().into()
}
