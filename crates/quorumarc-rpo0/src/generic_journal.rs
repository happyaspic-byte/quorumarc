use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"QGWL";
const VERSION: u8 = 1;
const MAX_PAYLOAD: usize = 65_536;
const HEADER_LEN: usize = 4 + 1 + 4 + 8 + 16 + 8 + 32;
const CHECKSUM_LEN: usize = 32;
const MAX_RECORD_LEN: usize = HEADER_LEN + MAX_PAYLOAD + CHECKSUM_LEN;
const MAX_WAL_BYTES: usize = crate::MAX_WAL_RECORDS as usize * MAX_RECORD_LEN;
const ROOT_DOMAIN: &[u8] = b"quorumarc/generic-journal/state-root/v1\0";
const RECORD_DOMAIN: &[u8] = b"quorumarc/generic-journal/record/v1\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericOperation {
    operation_id: [u8; 16],
    expected_commit: u64,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericAcknowledgement {
    pub operation_id: [u8; 16],
    pub commit_index: u64,
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericDurableReceipt {
    acknowledgement: GenericAcknowledgement,
    replica_id: String,
    location: DurableLocation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GenericProgress {
    pub commit_index: u64,
    pub state_root: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenericJournalError {
    ZeroOperationId,
    PayloadTooLarge,
    ConflictingDuplicate,
    StaleCommit,
    FutureCommit,
    Corrupt,
    CapacityExceeded,
    ReplicaIdentityCollision,
    ReplicaUnavailable,
    InvalidDurabilityReceipt,
    UncertainDurability,
    RecoveryMismatch,
}

#[derive(Clone, Debug, Default)]
pub struct GenericJournal {
    bytes: Vec<u8>,
    operations: BTreeMap<[u8; 16], (Vec<u8>, GenericAcknowledgement)>,
    progress: Option<GenericProgress>,
}

impl GenericOperation {
    pub fn new(
        operation_id: [u8; 16],
        expected_commit: u64,
        payload: &[u8],
    ) -> Result<Self, GenericJournalError> {
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(GenericJournalError::ZeroOperationId);
        }
        if payload.len() > MAX_PAYLOAD {
            return Err(GenericJournalError::PayloadTooLarge);
        }
        Ok(Self {
            operation_id,
            expected_commit,
            payload: payload.to_vec(),
        })
    }
}

impl GenericJournal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.operations.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    pub fn apply(
        &mut self,
        operation: GenericOperation,
    ) -> Result<GenericAcknowledgement, GenericJournalError> {
        if let Some((payload, acknowledged)) = self.operations.get(&operation.operation_id) {
            if payload == &operation.payload
                && operation
                    .expected_commit
                    .checked_add(1)
                    .is_some_and(|commit| commit == acknowledged.commit_index)
            {
                return Ok(*acknowledged);
            }
            return Err(GenericJournalError::ConflictingDuplicate);
        }
        let current = self.progress.map_or(0, |progress| progress.commit_index);
        if operation.expected_commit < current {
            return Err(GenericJournalError::StaleCommit);
        }
        if operation.expected_commit > current {
            return Err(GenericJournalError::FutureCommit);
        }
        let commit_index = current
            .checked_add(1)
            .ok_or(GenericJournalError::CapacityExceeded)?;
        if commit_index > crate::MAX_WAL_RECORDS {
            return Err(GenericJournalError::CapacityExceeded);
        }
        let previous_root = self
            .progress
            .map_or([0; 32], |progress| progress.state_root);
        let state_root = next_root(
            previous_root,
            commit_index,
            operation.operation_id,
            &operation.payload,
        );
        let encoded = encode_record(
            commit_index,
            operation.operation_id,
            operation.expected_commit,
            previous_root,
            &operation.payload,
        );
        self.bytes.extend_from_slice(&encoded);
        let acknowledgement = GenericAcknowledgement {
            operation_id: operation.operation_id,
            commit_index,
            state_root,
        };
        self.operations
            .insert(operation.operation_id, (operation.payload, acknowledgement));
        self.progress = Some(GenericProgress {
            commit_index,
            state_root,
        });
        Ok(acknowledgement)
    }

    pub fn recover(&self) -> Result<GenericProgress, GenericJournalError> {
        recover_bytes(&self.bytes)
    }

    pub fn corrupt_byte(&mut self, offset: usize) -> bool {
        if let Some(byte) = self.bytes.get_mut(offset) {
            *byte ^= 0x80;
            true
        } else {
            false
        }
    }
}

/// In-memory generic replica used to prove dual-receipt ACK rules.
#[derive(Clone, Debug)]
pub struct MemoryGenericReplica {
    replica_id: String,
    bytes: Vec<u8>,
    append_count: usize,
    fail_next: bool,
}

impl MemoryGenericReplica {
    #[must_use]
    pub fn new(replica_id: impl Into<String>) -> Self {
        Self {
            replica_id: replica_id.into(),
            bytes: Vec::new(),
            append_count: 0,
            fail_next: false,
        }
    }

    #[must_use]
    pub const fn append_count(&self) -> usize {
        self.append_count
    }

    pub fn fail_next(&mut self) {
        self.fail_next = true;
    }

    fn append(&mut self, encoded: &[u8]) -> Result<GenericDurableReceipt, GenericJournalError> {
        self.append_count = self.append_count.saturating_add(1);
        if self.fail_next {
            self.fail_next = false;
            return Err(GenericJournalError::ReplicaUnavailable);
        }
        if !self.bytes.ends_with(encoded) {
            self.bytes.extend_from_slice(encoded);
        }
        durable_receipt(
            &self.replica_id,
            DurableLocation::ProcessLocal(self.replica_id.clone()),
            encoded,
        )
    }
}

impl GenericReplicaSink for MemoryGenericReplica {
    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn durable_location(&self) -> Result<DurableLocation, GenericJournalError> {
        Ok(DurableLocation::ProcessLocal(self.replica_id.clone()))
    }

    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericDurableReceipt, GenericJournalError> {
        self.append(encoded)
    }
}

/// File-backed generic replica with dual-fsync receipts.
#[derive(Debug)]
pub struct FileGenericReplica {
    replica_id: String,
    path: PathBuf,
}

impl FileGenericReplica {
    #[must_use]
    pub fn new(replica_id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            replica_id: replica_id.into(),
            path: path.into(),
        }
    }
}

impl GenericReplicaSink for FileGenericReplica {
    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn durable_location(&self) -> Result<DurableLocation, GenericJournalError> {
        file_location(&self.path)
    }

    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericDurableReceipt, GenericJournalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        let metadata = file
            .metadata()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        if !metadata.is_file() {
            return Err(GenericJournalError::ReplicaUnavailable);
        }
        let location = DurableLocation::Inode {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let existing = read_bounded_file(&mut file)?;
        let progress = recover_bytes(&existing)?;
        let parsed = parse_one_record(encoded)?;
        if existing.ends_with(encoded) {
            if progress.commit_index != parsed.commit_index
                || progress.state_root != parsed.state_root
            {
                return Err(GenericJournalError::Corrupt);
            }
            file.sync_all()
                .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
            sync_parent_directory(&self.path)?;
            return durable_receipt(&self.replica_id, location, encoded);
        }
        if parsed.commit_index != progress.commit_index.saturating_add(1)
            || parsed.expected_commit != progress.commit_index
            || parsed.previous_root != progress.state_root
        {
            return Err(GenericJournalError::Corrupt);
        }
        file.write_all(encoded)
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        file.sync_all()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        sync_parent_directory(&self.path)?;
        durable_receipt(&self.replica_id, location, encoded)
    }
}

fn read_bounded_file(file: &mut File) -> Result<Vec<u8>, GenericJournalError> {
    let limit = u64::try_from(MAX_WAL_BYTES)
        .map_err(|_error| GenericJournalError::CapacityExceeded)?
        .saturating_add(1);
    let mut bytes = Vec::new();
    file.take(limit)
        .read_to_end(&mut bytes)
        .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
    if bytes.len() > MAX_WAL_BYTES {
        return Err(GenericJournalError::CapacityExceeded);
    }
    Ok(bytes)
}

fn sync_parent_directory(path: &Path) -> Result<(), GenericJournalError> {
    let parent = match path.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        Some(_) | None => Path::new("."),
    };
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_error| GenericJournalError::ReplicaUnavailable)
}

struct ParsedRecord {
    operation_id: [u8; 16],
    commit_index: u64,
    expected_commit: u64,
    previous_root: [u8; 32],
    state_root: [u8; 32],
    payload: Vec<u8>,
    acknowledgement: GenericAcknowledgement,
    record_end: usize,
}

fn parse_one_record(bytes: &[u8]) -> Result<ParsedRecord, GenericJournalError> {
    let parsed = parse_one_record_at(bytes, 0)?;
    if parsed.record_end != bytes.len() {
        return Err(GenericJournalError::Corrupt);
    }
    Ok(parsed)
}

fn parse_one_record_at(bytes: &[u8], cursor: usize) -> Result<ParsedRecord, GenericJournalError> {
    let header_end = cursor
        .checked_add(HEADER_LEN)
        .ok_or(GenericJournalError::Corrupt)?;
    if header_end > bytes.len()
        || &bytes[cursor..cursor + 4] != MAGIC
        || bytes[cursor + 4] != VERSION
    {
        return Err(GenericJournalError::Corrupt);
    }
    let payload_len = u32::from_be_bytes(
        bytes[cursor + 5..cursor + 9]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    ) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(GenericJournalError::Corrupt);
    }
    let record_end = header_end
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(CHECKSUM_LEN))
        .ok_or(GenericJournalError::Corrupt)?;
    if record_end > bytes.len() {
        return Err(GenericJournalError::Corrupt);
    }
    let checksum_start = record_end - CHECKSUM_LEN;
    if bytes[checksum_start..record_end] != record_checksum(&bytes[cursor..checksum_start]) {
        return Err(GenericJournalError::Corrupt);
    }
    let commit_index = u64::from_be_bytes(
        bytes[cursor + 9..cursor + 17]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    );
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&bytes[cursor + 17..cursor + 33]);
    let expected_commit = u64::from_be_bytes(
        bytes[cursor + 33..cursor + 41]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    );
    let mut previous_root = [0; 32];
    previous_root.copy_from_slice(&bytes[cursor + 41..header_end]);
    let payload = &bytes[header_end..checksum_start];
    let state_root = next_root(previous_root, commit_index, operation_id, payload);
    Ok(ParsedRecord {
        operation_id,
        commit_index,
        expected_commit,
        previous_root,
        state_root,
        payload: payload.to_vec(),
        acknowledgement: GenericAcknowledgement {
            operation_id,
            commit_index,
            state_root,
        },
        record_end,
    })
}

fn durable_receipt(
    replica_id: &str,
    location: DurableLocation,
    encoded: &[u8],
) -> Result<GenericDurableReceipt, GenericJournalError> {
    if replica_id.is_empty() {
        return Err(GenericJournalError::InvalidDurabilityReceipt);
    }
    let parsed = parse_one_record(encoded)?;
    Ok(GenericDurableReceipt {
        acknowledgement: GenericAcknowledgement {
            operation_id: parsed.operation_id,
            commit_index: parsed.commit_index,
            state_root: parsed.state_root,
        },
        replica_id: replica_id.to_owned(),
        location,
    })
}

/// Dual-receipt sink for generic chained records.
pub trait GenericReplicaSink {
    fn replica_id(&self) -> &str;
    fn durable_location(&self) -> Result<DurableLocation, GenericJournalError>;
    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericDurableReceipt, GenericJournalError>;
}

/// Physical replica identity used to refuse one-copy aliases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableLocation {
    ProcessLocal(String),
    Inode { device: u64, inode: u64 },
    AbsentPath(PathBuf),
}

/// Dual-receipt coordinator for generic journal records.
#[derive(Clone, Debug, Default)]
pub struct ReplicatedGenericJournal {
    journal: GenericJournal,
    uncertain: bool,
}

impl ReplicatedGenericJournal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
    }

    pub fn apply<L: GenericReplicaSink, R: GenericReplicaSink>(
        &mut self,
        operation: GenericOperation,
        left: &mut L,
        right: &mut R,
    ) -> Result<GenericAcknowledgement, GenericJournalError> {
        if self.uncertain {
            return Err(GenericJournalError::UncertainDurability);
        }
        if left.replica_id() == right.replica_id()
            || left.durable_location()? == right.durable_location()?
        {
            return Err(GenericJournalError::ReplicaIdentityCollision);
        }
        if let Some((payload, acknowledged)) = self.journal.operations.get(&operation.operation_id)
        {
            if payload == &operation.payload
                && operation
                    .expected_commit
                    .checked_add(1)
                    .is_some_and(|commit| commit == acknowledged.commit_index)
            {
                return Ok(*acknowledged);
            }
            return Err(GenericJournalError::ConflictingDuplicate);
        }
        let encoded = encode_pending(&self.journal, &operation)?;
        let left_receipt = match left.append_and_flush(&encoded) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.uncertain = true;
                return Err(error);
            }
        };
        let right_receipt = match right.append_and_flush(&encoded) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.uncertain = true;
                return Err(error);
            }
        };
        if left_receipt.acknowledgement != right_receipt.acknowledgement
            || left_receipt.replica_id == right_receipt.replica_id
            || left_receipt.location == right_receipt.location
        {
            self.uncertain = true;
            return Err(GenericJournalError::InvalidDurabilityReceipt);
        }
        let acknowledgement = self.journal.apply(operation)?;
        if acknowledgement != left_receipt.acknowledgement {
            self.uncertain = true;
            return Err(GenericJournalError::InvalidDurabilityReceipt);
        }
        Ok(acknowledgement)
    }

    /// Recovers only when both files contain identical valid chained records.
    pub fn recover_from_files(
        left: impl AsRef<Path>,
        right: impl AsRef<Path>,
    ) -> Result<Self, GenericJournalError> {
        let mut left_file = match File::open(left.as_ref()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(GenericJournalError::ReplicaUnavailable);
            }
            Err(_error) => return Err(GenericJournalError::ReplicaUnavailable),
        };
        let mut right_file = match File::open(right.as_ref()) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(GenericJournalError::ReplicaUnavailable);
            }
            Err(_error) => return Err(GenericJournalError::ReplicaUnavailable),
        };
        let left_meta = left_file
            .metadata()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        let right_meta = right_file
            .metadata()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        if !left_meta.is_file()
            || !right_meta.is_file()
            || (left_meta.dev(), left_meta.ino()) == (right_meta.dev(), right_meta.ino())
        {
            return Err(GenericJournalError::ReplicaIdentityCollision);
        }
        let left_bytes = read_bounded_file(&mut left_file)?;
        let right_bytes = read_bounded_file(&mut right_file)?;
        if left_bytes != right_bytes {
            return Err(GenericJournalError::RecoveryMismatch);
        }
        let progress = recover_bytes(&left_bytes)?;
        let mut journal = GenericJournal {
            bytes: left_bytes,
            operations: BTreeMap::new(),
            progress: if progress.commit_index == 0 {
                None
            } else {
                Some(progress)
            },
        };
        replay_operations(&mut journal)?;
        left_file
            .sync_all()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        right_file
            .sync_all()
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        sync_parent_directory(left.as_ref())?;
        sync_parent_directory(right.as_ref())?;
        Ok(Self {
            journal,
            uncertain: false,
        })
    }

    #[must_use]
    pub fn progress(&self) -> GenericProgress {
        self.journal.progress.unwrap_or(GenericProgress {
            commit_index: 0,
            state_root: [0; 32],
        })
    }
}

fn file_location(path: &Path) -> Result<DurableLocation, GenericJournalError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(GenericJournalError::ReplicaUnavailable);
            }
            Ok(DurableLocation::Inode {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DurableLocation::AbsentPath(normalized_absent_path(path)?))
        }
        Err(_error) => Err(GenericJournalError::ReplicaUnavailable),
    }
}

fn normalized_absent_path(path: &Path) -> Result<PathBuf, GenericJournalError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?
    };
    let file_name = absolute
        .file_name()
        .ok_or(GenericJournalError::ReplicaUnavailable)?;
    let parent = match absolute.parent() {
        Some(directory) if !directory.as_os_str().is_empty() => directory,
        Some(_) | None => Path::new("/"),
    };
    let canonical_parent = match std::fs::canonicalize(parent) {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => lexical_normalize(parent),
        Err(_error) => return Err(GenericJournalError::ReplicaUnavailable),
    };
    Ok(canonical_parent.join(file_name))
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            std::path::Component::RootDir => normalized.push("/"),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let _ = normalized.pop();
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    if normalized.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        normalized
    }
}

fn replay_operations(journal: &mut GenericJournal) -> Result<(), GenericJournalError> {
    let bytes = journal.bytes.clone();
    let mut cursor = 0_usize;
    let mut operations = BTreeMap::new();
    while cursor < bytes.len() {
        let parsed = parse_one_record_at(&bytes, cursor)?;
        if operations
            .insert(
                parsed.operation_id,
                (parsed.payload, parsed.acknowledgement),
            )
            .is_some()
        {
            return Err(GenericJournalError::Corrupt);
        }
        cursor = parsed.record_end;
    }
    journal.operations = operations;
    Ok(())
}

fn encode_pending(
    journal: &GenericJournal,
    operation: &GenericOperation,
) -> Result<Vec<u8>, GenericJournalError> {
    let current = journal.progress.map_or(0, |progress| progress.commit_index);
    if operation.expected_commit < current {
        return Err(GenericJournalError::StaleCommit);
    }
    if operation.expected_commit > current {
        return Err(GenericJournalError::FutureCommit);
    }
    let commit_index = current
        .checked_add(1)
        .ok_or(GenericJournalError::CapacityExceeded)?;
    if commit_index > crate::MAX_WAL_RECORDS {
        return Err(GenericJournalError::CapacityExceeded);
    }
    let previous_root = journal
        .progress
        .map_or([0; 32], |progress| progress.state_root);
    Ok(encode_record(
        commit_index,
        operation.operation_id,
        operation.expected_commit,
        previous_root,
        &operation.payload,
    ))
}

fn encode_record(
    commit_index: u64,
    operation_id: [u8; 16],
    expected_commit: u64,
    previous_root: [u8; 32],
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len() + CHECKSUM_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.push(VERSION);
    bytes.extend_from_slice(
        &u32::try_from(payload.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(&commit_index.to_be_bytes());
    bytes.extend_from_slice(&operation_id);
    bytes.extend_from_slice(&expected_commit.to_be_bytes());
    bytes.extend_from_slice(&previous_root);
    bytes.extend_from_slice(payload);
    bytes.extend_from_slice(&record_checksum(&bytes));
    bytes
}

fn recover_bytes(bytes: &[u8]) -> Result<GenericProgress, GenericJournalError> {
    let mut cursor = 0_usize;
    let mut progress = GenericProgress {
        commit_index: 0,
        state_root: [0; 32],
    };
    let mut operations = BTreeMap::new();
    while cursor < bytes.len() {
        let header_end = cursor
            .checked_add(HEADER_LEN)
            .ok_or(GenericJournalError::Corrupt)?;
        if header_end > bytes.len()
            || &bytes[cursor..cursor + 4] != MAGIC
            || bytes[cursor + 4] != VERSION
        {
            return Err(GenericJournalError::Corrupt);
        }
        let payload_len = u32::from_be_bytes(
            bytes[cursor + 5..cursor + 9]
                .try_into()
                .map_err(|_error| GenericJournalError::Corrupt)?,
        ) as usize;
        if payload_len > MAX_PAYLOAD {
            return Err(GenericJournalError::Corrupt);
        }
        let record_end = header_end
            .checked_add(payload_len)
            .and_then(|value| value.checked_add(CHECKSUM_LEN))
            .ok_or(GenericJournalError::Corrupt)?;
        if record_end > bytes.len() {
            return Err(GenericJournalError::Corrupt);
        }
        let checksum_start = record_end - CHECKSUM_LEN;
        if bytes[checksum_start..record_end] != record_checksum(&bytes[cursor..checksum_start]) {
            return Err(GenericJournalError::Corrupt);
        }
        let commit_index = u64::from_be_bytes(
            bytes[cursor + 9..cursor + 17]
                .try_into()
                .map_err(|_error| GenericJournalError::Corrupt)?,
        );
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&bytes[cursor + 17..cursor + 33]);
        if operation_id.iter().all(|byte| *byte == 0) {
            return Err(GenericJournalError::ZeroOperationId);
        }
        if commit_index > crate::MAX_WAL_RECORDS {
            return Err(GenericJournalError::CapacityExceeded);
        }
        let expected_commit = u64::from_be_bytes(
            bytes[cursor + 33..cursor + 41]
                .try_into()
                .map_err(|_error| GenericJournalError::Corrupt)?,
        );
        let mut previous_root = [0; 32];
        previous_root.copy_from_slice(&bytes[cursor + 41..header_end]);
        if commit_index != progress.commit_index.saturating_add(1)
            || expected_commit != progress.commit_index
            || previous_root != progress.state_root
            || operations.insert(operation_id, ()).is_some()
        {
            return Err(GenericJournalError::Corrupt);
        }
        let payload = &bytes[header_end..checksum_start];
        progress = GenericProgress {
            commit_index,
            state_root: next_root(previous_root, commit_index, operation_id, payload),
        };
        cursor = record_end;
    }
    Ok(progress)
}

fn next_root(
    previous_root: [u8; 32],
    commit_index: u64,
    operation_id: [u8; 16],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROOT_DOMAIN);
    hasher.update(previous_root);
    hasher.update(commit_index.to_be_bytes());
    hasher.update(operation_id);
    hasher.update(payload);
    hasher.finalize().into()
}

fn record_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RECORD_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}
