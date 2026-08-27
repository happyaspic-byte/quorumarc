use std::collections::BTreeMap;

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
