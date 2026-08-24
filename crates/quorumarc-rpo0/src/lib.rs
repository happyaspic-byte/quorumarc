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

mod codec;
mod counter;
mod error;
mod replica;

pub use codec::{recover_wal, RecoveredCounter, StateRoot, WalEntry};
pub use counter::{
    AcknowledgedWrite, CounterOperation, OperationId, ReplicatedCounter, WorkloadProgress,
};
pub use error::{ReplicaError, Rpo0Error, WalCorruption};
pub use replica::{DurableReceipt, Fault, FileReplica, MemoryReplica, ReplicaSink};
