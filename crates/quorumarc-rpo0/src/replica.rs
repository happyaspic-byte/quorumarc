use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::codec::record_checksum;
use crate::{ReplicaError, WalEntry, recover_wal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableReceipt {
    pub replica_id: String,
    pub commit_index: u64,
    pub record_checksum: u32,
}

pub trait ReplicaSink {
    fn replica_id(&self) -> &str;

    /// Append the exact canonical record and make it durable before returning.
    fn append_and_flush(
        &mut self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ReplicaError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    FailBeforeAppend,
    TruncateAppend(usize),
    CorruptAppend,
    InvalidReceipt,
}

#[derive(Debug, Clone)]
pub struct MemoryReplica {
    replica_id: String,
    bytes: Vec<u8>,
    next_fault: Fault,
    append_count: usize,
}

impl MemoryReplica {
    pub fn new(replica_id: impl Into<String>) -> Self {
        Self {
            replica_id: replica_id.into(),
            bytes: Vec::new(),
            next_fault: Fault::None,
            append_count: 0,
        }
    }

    pub fn inject_once(&mut self, fault: Fault) {
        self.next_fault = fault;
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn append_count(&self) -> usize {
        self.append_count
    }

    pub fn corrupt_byte(&mut self, offset: usize) -> bool {
        match self.bytes.get_mut(offset) {
            Some(byte) => {
                *byte ^= 0x80;
                true
            }
            None => false,
        }
    }
}

impl ReplicaSink for MemoryReplica {
    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn append_and_flush(
        &mut self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ReplicaError> {
        self.append_count = self.append_count.saturating_add(1);
        if validate_existing_wal(&self.bytes, entry, canonical_record)?
            == AppendDisposition::AlreadyDurable
        {
            return durable_receipt(&self.replica_id, entry, canonical_record);
        }
        let fault = core::mem::replace(&mut self.next_fault, Fault::None);
        match fault {
            Fault::None => self.bytes.extend_from_slice(canonical_record),
            Fault::FailBeforeAppend => return Err(ReplicaError::InjectedFailure),
            Fault::TruncateAppend(length) => {
                let end = length.min(canonical_record.len());
                self.bytes.extend_from_slice(&canonical_record[..end]);
                return Err(ReplicaError::InjectedFailure);
            }
            Fault::CorruptAppend => {
                let mut corrupted = canonical_record.to_vec();
                if let Some(byte) = corrupted.get_mut(0) {
                    *byte ^= 0xff;
                }
                self.bytes.extend_from_slice(&corrupted);
                return Err(ReplicaError::InjectedFailure);
            }
            Fault::InvalidReceipt => {
                self.bytes.extend_from_slice(canonical_record);
                return Ok(DurableReceipt {
                    replica_id: self.replica_id.clone(),
                    commit_index: entry.commit_index.saturating_add(1),
                    record_checksum: 0,
                });
            }
        }
        durable_receipt(&self.replica_id, entry, canonical_record)
    }
}

#[derive(Debug)]
/// A Gate 1A lab adapter. The caller must enforce exclusive writer ownership;
/// this type detects corrupt/non-contiguous WAL contents but does not provide
/// cross-process fencing or file locking.
pub struct FileReplica {
    replica_id: String,
    path: PathBuf,
}

impl FileReplica {
    pub fn new(replica_id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            replica_id: replica_id.into(),
            path: path.into(),
        }
    }

    pub fn read_all(&self) -> Result<Vec<u8>, ReplicaError> {
        read_file_or_empty(&self.path).map_err(ReplicaError::Io)
    }
}

impl ReplicaSink for FileReplica {
    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn append_and_flush(
        &mut self,
        entry: &WalEntry,
        canonical_record: &[u8],
    ) -> Result<DurableReceipt, ReplicaError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)?;
        let mut existing = Vec::new();
        file.read_to_end(&mut existing)?;
        // The first durability response can be lost. Only an exact canonical
        // record already at the validated WAL tail is an idempotent success;
        // changed or older retries remain fail-closed.
        if validate_existing_wal(&existing, entry, canonical_record)?
            == AppendDisposition::AlreadyDurable
        {
            file.sync_all()?;
            sync_parent_directory(&self.path)?;
            return durable_receipt(&self.replica_id, entry, canonical_record);
        }
        file.write_all(canonical_record)?;
        file.sync_all()?;
        sync_parent_directory(&self.path)?;
        durable_receipt(&self.replica_id, entry, canonical_record)
    }
}

fn sync_parent_directory(path: &Path) -> Result<(), std::io::Error> {
    let parent = match path.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)?.sync_all()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppendDisposition {
    Append,
    AlreadyDurable,
}

fn validate_existing_wal(
    bytes: &[u8],
    entry: &WalEntry,
    canonical_record: &[u8],
) -> Result<AppendDisposition, ReplicaError> {
    if entry.encode() != canonical_record {
        return Err(ReplicaError::InvalidReceipt);
    }
    let recovered = recover_wal(bytes).map_err(ReplicaError::CorruptWal)?;
    if recovered.commit_index == entry.commit_index
        && recovered.value == entry.value
        && bytes.ends_with(canonical_record)
    {
        return Ok(AppendDisposition::AlreadyDurable);
    }
    if recovered.commit_index.checked_add(1) != Some(entry.commit_index)
        || recovered.value != entry.previous_value
    {
        return Err(ReplicaError::SequenceMismatch);
    }
    Ok(AppendDisposition::Append)
}

fn durable_receipt(
    replica_id: &str,
    entry: &WalEntry,
    canonical_record: &[u8],
) -> Result<DurableReceipt, ReplicaError> {
    Ok(DurableReceipt {
        replica_id: replica_id.to_owned(),
        commit_index: entry.commit_index,
        record_checksum: record_checksum(canonical_record)
            .map_err(|_| ReplicaError::InvalidReceipt)?,
    })
}

fn read_file_or_empty(path: &Path) -> Result<Vec<u8>, std::io::Error> {
    match File::open(path) {
        Ok(mut file) => {
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            Ok(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}
