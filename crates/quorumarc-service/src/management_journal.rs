use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"QARCMJ01";
const IDENTITY_LEN: usize = 16;
const OPERATION_ID_LEN: usize = 16;
const DIGEST_LEN: usize = 32;
const RECORD_LEN: usize = MAGIC.len() + IDENTITY_LEN + 8 + OPERATION_ID_LEN + DIGEST_LEN;

/// Durable, restart-safe management anti-replay journal.
#[derive(Debug)]
pub struct ManagementJournal {
    path: PathBuf,
    identity: [u8; IDENTITY_LEN],
    highest_sequence: u64,
    last_operation: Option<ManagementOperation>,
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
    Io,
}

impl ManagementOperation {
    /// Builds a strictly sequenced management operation.
    pub fn new(
        sequence: u64,
        operation_id: [u8; OPERATION_ID_LEN],
        digest: [u8; DIGEST_LEN],
    ) -> Result<Self, JournalError> {
        if sequence == 0 {
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
    /// Opens or creates an identity-bound management journal.
    pub fn open(directory: &Path, identity: [u8; IDENTITY_LEN]) -> Result<Self, JournalError> {
        fs::create_dir_all(directory).map_err(|_error| JournalError::Io)?;
        let path = directory.join("management.journal");
        if path.exists() {
            let mut journal = recover(&path)?;
            if journal.identity != identity {
                return Err(JournalError::IdentityMismatch);
            }
            journal.path = path;
            Ok(journal)
        } else {
            let journal = Self {
                path,
                identity,
                highest_sequence: 0,
                last_operation: None,
            };
            journal.persist()?;
            Ok(journal)
        }
    }

    /// Highest committed sequence.
    #[must_use]
    pub const fn highest_sequence(&self) -> u64 {
        self.highest_sequence
    }

    /// Records an exact-retry-safe management operation.
    pub fn record(
        &mut self,
        operation: ManagementOperation,
    ) -> Result<ManagementOutcome, JournalError> {
        if let Some(last) = self.last_operation {
            if last.sequence == operation.sequence {
                if last == operation {
                    return Ok(ManagementOutcome::AlreadyDurable);
                }
                if last.operation_id == operation.operation_id {
                    return Err(JournalError::ConflictingOperation);
                }
                return Err(JournalError::StaleSequence);
            }
            if operation.sequence <= last.sequence {
                return Err(JournalError::StaleSequence);
            }
            if operation.sequence != last.sequence.saturating_add(1) {
                return Err(JournalError::StaleSequence);
            }
        } else if operation.sequence != 1 {
            return Err(JournalError::StaleSequence);
        }
        self.last_operation = Some(operation);
        self.highest_sequence = operation.sequence;
        self.persist()?;
        Ok(ManagementOutcome::Committed)
    }

    fn persist(&self) -> Result<(), JournalError> {
        let temporary = self.path.with_extension("journal.tmp");
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temporary)
            .map_err(|_error| JournalError::Io)?;
        file.write_all(&encode(self.identity, self.last_operation))
            .and_then(|()| file.sync_all())
            .map_err(|_error| JournalError::Io)?;
        fs::rename(&temporary, &self.path).map_err(|_error| JournalError::Io)?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_error| JournalError::Io)?;
        }
        Ok(())
    }
}

fn recover(path: &Path) -> Result<ManagementJournal, JournalError> {
    let mut bytes = Vec::new();
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_error| JournalError::Io)?;
    if bytes.len() != RECORD_LEN || &bytes[..MAGIC.len()] != MAGIC {
        return Err(JournalError::Io);
    }
    let mut identity = [0_u8; IDENTITY_LEN];
    identity.copy_from_slice(&bytes[MAGIC.len()..MAGIC.len() + IDENTITY_LEN]);
    let sequence_offset = MAGIC.len() + IDENTITY_LEN;
    let sequence = u64::from_be_bytes(
        bytes[sequence_offset..sequence_offset + 8]
            .try_into()
            .map_err(|_error| JournalError::Io)?,
    );
    let mut operation_id = [0_u8; OPERATION_ID_LEN];
    let id_offset = sequence_offset + 8;
    operation_id.copy_from_slice(&bytes[id_offset..id_offset + OPERATION_ID_LEN]);
    let mut digest = [0_u8; DIGEST_LEN];
    let digest_offset = id_offset + OPERATION_ID_LEN;
    digest.copy_from_slice(&bytes[digest_offset..digest_offset + DIGEST_LEN]);
    let last_operation = if sequence == 0 {
        None
    } else {
        Some(ManagementOperation {
            sequence,
            operation_id,
            digest,
        })
    };
    Ok(ManagementJournal {
        path: path.to_path_buf(),
        identity,
        highest_sequence: sequence,
        last_operation,
    })
}

fn encode(
    identity: [u8; IDENTITY_LEN],
    last_operation: Option<ManagementOperation>,
) -> [u8; RECORD_LEN] {
    let mut bytes = [0_u8; RECORD_LEN];
    bytes[..MAGIC.len()].copy_from_slice(MAGIC);
    bytes[MAGIC.len()..MAGIC.len() + IDENTITY_LEN].copy_from_slice(&identity);
    if let Some(operation) = last_operation {
        let sequence_offset = MAGIC.len() + IDENTITY_LEN;
        bytes[sequence_offset..sequence_offset + 8]
            .copy_from_slice(&operation.sequence.to_be_bytes());
        let id_offset = sequence_offset + 8;
        bytes[id_offset..id_offset + OPERATION_ID_LEN].copy_from_slice(&operation.operation_id);
        let digest_offset = id_offset + OPERATION_ID_LEN;
        bytes[digest_offset..digest_offset + DIGEST_LEN].copy_from_slice(&operation.digest);
    }
    bytes
}
