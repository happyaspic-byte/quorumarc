use core::fmt;
use std::io;

use crate::OperationId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalCorruption {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u8),
    InvalidLength,
    ChecksumMismatch,
    NonContiguousCommitIndex,
    PreviousValueMismatch,
    ValueMismatch,
    DuplicateOperationId,
}

impl fmt::Display for WalCorruption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "WAL corruption: {self:?}")
    }
}

impl std::error::Error for WalCorruption {}

#[derive(Debug)]
pub enum ReplicaError {
    Io(io::Error),
    InjectedFailure,
    InvalidReceipt,
    CorruptWal(WalCorruption),
    SequenceMismatch,
}

impl fmt::Display for ReplicaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "replica I/O failed: {error}"),
            Self::InjectedFailure => formatter.write_str("replica fault was injected"),
            Self::InvalidReceipt => formatter.write_str("replica returned an invalid receipt"),
            Self::CorruptWal(corruption) => corruption.fmt(formatter),
            Self::SequenceMismatch => {
                formatter.write_str("replica WAL does not precede the proposed record")
            }
        }
    }
}

impl std::error::Error for ReplicaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::CorruptWal(corruption) => Some(corruption),
            Self::InjectedFailure | Self::InvalidReceipt | Self::SequenceMismatch => None,
        }
    }
}

impl From<io::Error> for ReplicaError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug)]
pub enum Rpo0Error {
    ZeroIncrement,
    CounterOverflow,
    StaleOperation {
        expected: u64,
        actual: u64,
    },
    OutOfOrderOperation {
        expected: u64,
        actual: u64,
    },
    ConflictingDuplicate(OperationId),
    ReplicaMissing(&'static str),
    ReplicaUnavailable {
        replica: &'static str,
        source: ReplicaError,
    },
    ReplicaIdentityCollision,
    InvalidDurabilityReceipt(&'static str),
    UncertainDurability,
    RecoveryMismatch,
    CorruptWal(WalCorruption),
}

impl fmt::Display for Rpo0Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroIncrement => formatter.write_str("counter increment must be positive"),
            Self::CounterOverflow => formatter.write_str("counter would overflow"),
            Self::StaleOperation { expected, actual } => {
                write!(formatter, "stale operation: expected index {expected}, actual {actual}")
            }
            Self::OutOfOrderOperation { expected, actual } => write!(
                formatter,
                "out-of-order operation: expected index {expected}, actual {actual}"
            ),
            Self::ConflictingDuplicate(operation_id) => {
                write!(formatter, "operation ID {operation_id} was reused with different content")
            }
            Self::ReplicaMissing(replica) => {
                write!(formatter, "required {replica} replica is missing")
            }
            Self::ReplicaUnavailable { replica, source } => {
                write!(formatter, "{replica} replica did not confirm durability: {source}")
            }
            Self::ReplicaIdentityCollision => {
                formatter.write_str("two durable receipts identified the same replica")
            }
            Self::InvalidDurabilityReceipt(replica) => {
                write!(formatter, "{replica} replica returned a receipt for different bytes")
            }
            Self::UncertainDurability => formatter.write_str(
                "durability is uncertain after a replica failure; recovery is required",
            ),
            Self::RecoveryMismatch => {
                formatter.write_str("replicas do not contain identical recovered state")
            }
            Self::CorruptWal(corruption) => corruption.fmt(formatter),
        }
    }
}

impl std::error::Error for Rpo0Error {}

impl From<WalCorruption> for Rpo0Error {
    fn from(value: WalCorruption) -> Self {
        Self::CorruptWal(value)
    }
}
