use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"QGWL";
const VERSION: u8 = 1;
const MAX_PAYLOAD: usize = 65_536;
const HEADER_LEN: usize = 4 + 1 + 4 + 8 + 16 + 8 + 32;
const CHECKSUM_LEN: usize = 32;
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
                && operation.expected_commit + 1 == acknowledged.commit_index
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

    fn append(&mut self, encoded: &[u8]) -> Result<GenericAcknowledgement, GenericJournalError> {
        self.append_count = self.append_count.saturating_add(1);
        if self.fail_next {
            self.fail_next = false;
            return Err(GenericJournalError::ReplicaUnavailable);
        }
        if !self.bytes.ends_with(encoded) {
            self.bytes.extend_from_slice(encoded);
        }
        receipt_from_encoded(&self.replica_id, encoded)
    }
}

impl GenericReplicaSink for MemoryGenericReplica {
    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericAcknowledgement, GenericJournalError> {
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

    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericAcknowledgement, GenericJournalError> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
        let mut existing = Vec::new();
        file.read_to_end(&mut existing)
            .map_err(|_error| GenericJournalError::ReplicaUnavailable)?;
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
            return receipt_from_encoded(&self.replica_id, encoded);
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
        receipt_from_encoded(&self.replica_id, encoded)
    }
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
}

fn parse_one_record(bytes: &[u8]) -> Result<ParsedRecord, GenericJournalError> {
    if bytes.len() < HEADER_LEN + CHECKSUM_LEN || &bytes[..4] != MAGIC || bytes[4] != VERSION {
        return Err(GenericJournalError::Corrupt);
    }
    let payload_len = u32::from_be_bytes(
        bytes[5..9]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    ) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(GenericJournalError::Corrupt);
    }
    let record_end = HEADER_LEN
        .checked_add(payload_len)
        .and_then(|value| value.checked_add(CHECKSUM_LEN))
        .ok_or(GenericJournalError::Corrupt)?;
    if record_end != bytes.len() {
        return Err(GenericJournalError::Corrupt);
    }
    let checksum_start = record_end - CHECKSUM_LEN;
    if bytes[checksum_start..record_end] != record_checksum(&bytes[..checksum_start]) {
        return Err(GenericJournalError::Corrupt);
    }
    let commit_index = u64::from_be_bytes(
        bytes[9..17]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    );
    let mut operation_id = [0; 16];
    operation_id.copy_from_slice(&bytes[17..33]);
    let expected_commit = u64::from_be_bytes(
        bytes[33..41]
            .try_into()
            .map_err(|_error| GenericJournalError::Corrupt)?,
    );
    let mut previous_root = [0; 32];
    previous_root.copy_from_slice(&bytes[41..HEADER_LEN]);
    let payload = &bytes[HEADER_LEN..checksum_start];
    Ok(ParsedRecord {
        operation_id,
        commit_index,
        expected_commit,
        previous_root,
        state_root: next_root(previous_root, commit_index, operation_id, payload),
    })
}

fn receipt_from_encoded(
    replica_id: &str,
    encoded: &[u8],
) -> Result<GenericAcknowledgement, GenericJournalError> {
    if replica_id.is_empty() {
        return Err(GenericJournalError::InvalidDurabilityReceipt);
    }
    let parsed = parse_one_record(encoded)?;
    Ok(GenericAcknowledgement {
        operation_id: parsed.operation_id,
        commit_index: parsed.commit_index,
        state_root: parsed.state_root,
    })
}

/// Dual-receipt sink for generic chained records.
pub trait GenericReplicaSink {
    fn replica_id(&self) -> &str;
    fn append_and_flush(
        &mut self,
        encoded: &[u8],
    ) -> Result<GenericAcknowledgement, GenericJournalError>;
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
        if left.replica_id() == right.replica_id() {
            return Err(GenericJournalError::ReplicaIdentityCollision);
        }
        if let Some((payload, acknowledged)) = self.journal.operations.get(&operation.operation_id)
        {
            if payload == &operation.payload
                && operation.expected_commit + 1 == acknowledged.commit_index
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
        if left_receipt != right_receipt {
            self.uncertain = true;
            return Err(GenericJournalError::InvalidDurabilityReceipt);
        }
        let acknowledgement = self.journal.apply(operation)?;
        if acknowledgement != left_receipt {
            self.uncertain = true;
            return Err(GenericJournalError::InvalidDurabilityReceipt);
        }
        Ok(acknowledgement)
    }
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
