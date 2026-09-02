//! A deliberately small RPO-0 demonstration workload for the Gate 1A lab.
//!
//! This crate is not a general-purpose database. It demonstrates one safety
//! property: a counter operation is acknowledged only after two distinct
//! replica sinks report that the exact WAL record is durable.

#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![forbid(unsafe_code)]

mod ack_index;
mod codec;
mod counter;
mod error;
mod generic_journal;
mod replica;

pub const MAX_WAL_RECORDS: u64 = 1_024;

pub use ack_index::{AckIndexError, AckPreflight, DurableAckIndex};
pub use codec::{
    RecoveredCounter, RecoveredWrite, StateRoot, WalEntry, decode_wal_records, recover_wal,
};
pub use counter::{
    AcknowledgedWrite, CounterOperation, OperationId, OperationPreflight, ReplicatedCounter,
    WorkloadProgress,
};
pub use error::{ReplicaError, Rpo0Error, WalCorruption};
pub use generic_journal::{
    DurableLocation, FileGenericReplica, FileSegmentStore, GenericAcknowledgement, GenericJournal,
    GenericJournalError, GenericOperation, GenericProgress, GenericReplicaSink,
    GenericSegmentManifest, MemoryGenericReplica, ReplicatedGenericJournal, SealedSegment,
};
pub use replica::{DurableReceipt, Fault, FileReplica, MemoryReplica, ReplicaSink};
