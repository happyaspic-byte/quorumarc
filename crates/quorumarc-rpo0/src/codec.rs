use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::{CounterOperation, OperationId, WalCorruption};

const MAGIC: [u8; 4] = *b"QAWL";
const VERSION: u8 = 1;
const PAYLOAD_LENGTH: usize = 48;
const HEADER_LENGTH: usize = 9;
const CHECKSUM_LENGTH: usize = 4;
pub(crate) const RECORD_LENGTH: usize = HEADER_LENGTH + PAYLOAD_LENGTH + CHECKSUM_LENGTH;
const STATE_DOMAIN: &[u8] = b"quorumarc-rpo0-state-root-v1\0";

pub type StateRoot = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalEntry {
    pub commit_index: u64,
    pub operation_id: OperationId,
    pub previous_value: u64,
    pub increment: u64,
    pub value: u64,
}

impl WalEntry {
    pub(crate) fn from_operation(
        commit_index: u64,
        previous_value: u64,
        operation: CounterOperation,
    ) -> Result<Self, crate::Rpo0Error> {
        let value = previous_value
            .checked_add(operation.increment)
            .ok_or(crate::Rpo0Error::CounterOverflow)?;
        Ok(Self {
            commit_index,
            operation_id: operation.id,
            previous_value,
            increment: operation.increment,
            value,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(RECORD_LENGTH);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(&(PAYLOAD_LENGTH as u32).to_be_bytes());
        bytes.extend_from_slice(&self.commit_index.to_be_bytes());
        bytes.extend_from_slice(&self.operation_id.into_bytes());
        bytes.extend_from_slice(&self.previous_value.to_be_bytes());
        bytes.extend_from_slice(&self.increment.to_be_bytes());
        bytes.extend_from_slice(&self.value.to_be_bytes());
        let checksum = crc32(&bytes);
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredCounter {
    pub commit_index: u64,
    pub value: u64,
    pub state_root: StateRoot,
    pub(crate) operations: BTreeMap<OperationId, RecoveredOperation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecoveredOperation {
    pub(crate) commit_index: u64,
    pub(crate) expected_commit_index: u64,
    pub(crate) increment: u64,
    pub(crate) value: u64,
    pub(crate) state_root: StateRoot,
    pub(crate) record_checksum: u32,
}

impl RecoveredCounter {
    pub fn empty() -> Self {
        Self {
            commit_index: 0,
            value: 0,
            state_root: initial_state_root(),
            operations: BTreeMap::new(),
        }
    }
}

pub fn recover_wal(bytes: &[u8]) -> Result<RecoveredCounter, WalCorruption> {
    if bytes.is_empty() {
        return Ok(RecoveredCounter::empty());
    }
    let records = bytes.chunks_exact(RECORD_LENGTH);
    if !records.remainder().is_empty() {
        return Err(WalCorruption::Truncated);
    }

    let mut recovered = RecoveredCounter::empty();
    for record in records {
        let entry = decode_record(record)?;
        if entry.commit_index != recovered.commit_index.saturating_add(1) {
            return Err(WalCorruption::NonContiguousCommitIndex);
        }
        if entry.previous_value != recovered.value {
            return Err(WalCorruption::PreviousValueMismatch);
        }
        let calculated_value = entry
            .previous_value
            .checked_add(entry.increment)
            .ok_or(WalCorruption::ValueMismatch)?;
        if entry.increment == 0 || calculated_value != entry.value {
            return Err(WalCorruption::ValueMismatch);
        }
        if recovered.operations.contains_key(&entry.operation_id) {
            return Err(WalCorruption::DuplicateOperationId);
        }
        recovered.state_root = next_state_root(recovered.state_root, record);
        recovered.commit_index = entry.commit_index;
        recovered.value = entry.value;
        recovered.operations.insert(
            entry.operation_id,
            RecoveredOperation {
                commit_index: entry.commit_index,
                expected_commit_index: entry.commit_index.saturating_sub(1),
                increment: entry.increment,
                value: entry.value,
                state_root: recovered.state_root,
                record_checksum: recorded_checksum(record)?,
            },
        );
    }
    Ok(recovered)
}

fn decode_record(record: &[u8]) -> Result<WalEntry, WalCorruption> {
    if record.len() != RECORD_LENGTH {
        return Err(WalCorruption::Truncated);
    }
    if record.get(0..4) != Some(MAGIC.as_slice()) {
        return Err(WalCorruption::InvalidMagic);
    }
    let version = *record.get(4).ok_or(WalCorruption::Truncated)?;
    if version != VERSION {
        return Err(WalCorruption::UnsupportedVersion(version));
    }
    let payload_length = read_u32(record, 5)? as usize;
    if payload_length != PAYLOAD_LENGTH {
        return Err(WalCorruption::InvalidLength);
    }
    let checksum_offset = RECORD_LENGTH - CHECKSUM_LENGTH;
    let recorded_checksum = read_u32(record, checksum_offset)?;
    if crc32(&record[..checksum_offset]) != recorded_checksum {
        return Err(WalCorruption::ChecksumMismatch);
    }
    let operation_bytes: [u8; 16] = record
        .get(17..33)
        .ok_or(WalCorruption::Truncated)?
        .try_into()
        .map_err(|_| WalCorruption::Truncated)?;
    Ok(WalEntry {
        commit_index: read_u64(record, 9)?,
        operation_id: OperationId::new(operation_bytes),
        previous_value: read_u64(record, 33)?,
        increment: read_u64(record, 41)?,
        value: read_u64(record, 49)?,
    })
}

pub(crate) fn record_checksum(record: &[u8]) -> Result<u32, WalCorruption> {
    if record.len() != RECORD_LENGTH {
        return Err(WalCorruption::InvalidLength);
    }
    read_u32(record, RECORD_LENGTH - CHECKSUM_LENGTH)
}

fn recorded_checksum(record: &[u8]) -> Result<u32, WalCorruption> {
    read_u32(record, RECORD_LENGTH - CHECKSUM_LENGTH)
}

pub(crate) fn next_state_root(previous: StateRoot, record: &[u8]) -> StateRoot {
    let mut digest = Sha256::new();
    digest.update(STATE_DOMAIN);
    digest.update(previous);
    digest.update(record);
    digest.finalize().into()
}

fn initial_state_root() -> StateRoot {
    let mut digest = Sha256::new();
    digest.update(STATE_DOMAIN);
    digest.update(b"empty");
    digest.finalize().into()
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, WalCorruption> {
    let array: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or(WalCorruption::Truncated)?
        .try_into()
        .map_err(|_| WalCorruption::Truncated)?;
    Ok(u32::from_be_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, WalCorruption> {
    let array: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .ok_or(WalCorruption::Truncated)?
        .try_into()
        .map_err(|_| WalCorruption::Truncated)?;
    Ok(u64::from_be_bytes(array))
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}
