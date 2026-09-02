use std::collections::BTreeMap;
use std::fmt;

use crate::codec::{next_state_root, record_checksum};
use crate::{DurableReceipt, RecoveredCounter, ReplicaSink, Rpo0Error, StateRoot, WalEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId([u8; 16]);

impl OperationId {
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterOperation {
    pub id: OperationId,
    /// The last committed index observed by the caller.
    pub expected_commit_index: u64,
    pub increment: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationPreflight {
    Exact(AcknowledgedWrite),
    Fresh,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgedWrite {
    pub operation_id: OperationId,
    pub commit_index: u64,
    pub value: u64,
    pub state_root: StateRoot,
    pub replica_receipts: [DurableReceipt; 2],
}

/// The fields that a promotion envelope must bind for this workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkloadProgress {
    pub durable_commit_index: u64,
    pub state_root: StateRoot,
}

#[derive(Debug, Clone)]
struct AppliedOperation {
    increment: u64,
    expected_commit_index: u64,
    acknowledgement: AcknowledgedWrite,
}

#[derive(Debug, Clone)]
pub struct ReplicatedCounter {
    commit_index: u64,
    value: u64,
    state_root: StateRoot,
    operations: BTreeMap<OperationId, AppliedOperation>,
    uncertain: bool,
}

impl ReplicatedCounter {
    pub fn new() -> Self {
        let empty = RecoveredCounter::empty();
        Self {
            commit_index: empty.commit_index,
            value: empty.value,
            state_root: empty.state_root,
            operations: BTreeMap::new(),
            uncertain: false,
        }
    }

    pub fn from_recovered(
        left: RecoveredCounter,
        right: RecoveredCounter,
    ) -> Result<Self, Rpo0Error> {
        Self::from_recovered_with_replica_ids(left, right, "recovered-left", "recovered-right")
    }

    pub fn from_recovered_with_replica_ids(
        left: RecoveredCounter,
        right: RecoveredCounter,
        left_replica_id: impl Into<String>,
        right_replica_id: impl Into<String>,
    ) -> Result<Self, Rpo0Error> {
        if left != right {
            return Err(Rpo0Error::RecoveryMismatch);
        }
        let left_replica_id = left_replica_id.into();
        let right_replica_id = right_replica_id.into();
        if left_replica_id == right_replica_id {
            return Err(Rpo0Error::ReplicaIdentityCollision);
        }
        let operations = left
            .operations
            .iter()
            .map(|(operation_id, recovered)| {
                let acknowledgement = AcknowledgedWrite {
                    operation_id: *operation_id,
                    commit_index: recovered.commit_index,
                    value: recovered.value,
                    state_root: recovered.state_root,
                    replica_receipts: [
                        recovery_receipt(
                            &left_replica_id,
                            recovered.commit_index,
                            recovered.record_checksum,
                        ),
                        recovery_receipt(
                            &right_replica_id,
                            recovered.commit_index,
                            recovered.record_checksum,
                        ),
                    ],
                };
                (
                    *operation_id,
                    AppliedOperation {
                        increment: recovered.increment,
                        expected_commit_index: recovered.expected_commit_index,
                        acknowledgement,
                    },
                )
            })
            .collect();
        Ok(Self {
            commit_index: left.commit_index,
            value: left.value,
            state_root: left.state_root,
            operations,
            uncertain: false,
        })
    }

    pub const fn commit_index(&self) -> u64 {
        self.commit_index
    }

    pub const fn value(&self) -> u64 {
        self.value
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn promotion_progress(&self) -> WorkloadProgress {
        WorkloadProgress {
            durable_commit_index: self.commit_index,
            state_root: self.state_root,
        }
    }

    pub const fn is_uncertain(&self) -> bool {
        self.uncertain
    }

    pub fn preflight(&self, operation: CounterOperation) -> Result<OperationPreflight, Rpo0Error> {
        if self.uncertain {
            return Err(Rpo0Error::UncertainDurability);
        }
        if let Some(applied) = self.operations.get(&operation.id) {
            if applied.increment == operation.increment
                && applied.expected_commit_index == operation.expected_commit_index
            {
                return Ok(OperationPreflight::Exact(applied.acknowledgement.clone()));
            }
            return Err(Rpo0Error::ConflictingDuplicate(operation.id));
        }
        if operation.increment == 0 {
            return Err(Rpo0Error::ZeroIncrement);
        }
        if operation.expected_commit_index < self.commit_index {
            return Err(Rpo0Error::StaleOperation {
                expected: operation.expected_commit_index,
                actual: self.commit_index,
            });
        }
        if operation.expected_commit_index > self.commit_index {
            return Err(Rpo0Error::OutOfOrderOperation {
                expected: operation.expected_commit_index,
                actual: self.commit_index,
            });
        }
        if self.commit_index >= crate::MAX_WAL_RECORDS {
            return Err(Rpo0Error::CapacityExceeded);
        }
        if self.commit_index.checked_add(1).is_none()
            || self.value.checked_add(operation.increment).is_none()
        {
            return Err(Rpo0Error::CounterOverflow);
        }
        Ok(OperationPreflight::Fresh)
    }

    pub fn apply_available(
        &mut self,
        operation: CounterOperation,
        left: Option<&mut dyn ReplicaSink>,
        right: Option<&mut dyn ReplicaSink>,
    ) -> Result<AcknowledgedWrite, Rpo0Error> {
        let left = left.ok_or(Rpo0Error::ReplicaMissing("left"))?;
        let right = right.ok_or(Rpo0Error::ReplicaMissing("right"))?;
        self.apply(operation, left, right)
    }

    pub fn apply<L: ReplicaSink + ?Sized, R: ReplicaSink + ?Sized>(
        &mut self,
        operation: CounterOperation,
        left: &mut L,
        right: &mut R,
    ) -> Result<AcknowledgedWrite, Rpo0Error> {
        match self.preflight(operation)? {
            OperationPreflight::Exact(acknowledgement) => return Ok(acknowledgement),
            OperationPreflight::Fresh => {}
        }
        let left_replica_id = left.replica_id().to_owned();
        let right_replica_id = right.replica_id().to_owned();
        if left_replica_id == right_replica_id {
            return Err(Rpo0Error::ReplicaIdentityCollision);
        }

        let entry = WalEntry::from_operation(
            self.commit_index
                .checked_add(1)
                .ok_or(Rpo0Error::CounterOverflow)?,
            self.value,
            operation,
        )?;
        let canonical_record = entry.encode();
        let checksum = record_checksum(&canonical_record)?;

        let left_receipt = match left.append_and_flush(&entry, &canonical_record) {
            Ok(receipt) => receipt,
            Err(source) => {
                self.uncertain = true;
                return Err(Rpo0Error::ReplicaUnavailable {
                    replica: "left",
                    source,
                });
            }
        };
        if let Err(error) =
            validate_receipt("left", &left_replica_id, &left_receipt, &entry, checksum)
        {
            self.uncertain = true;
            return Err(error);
        }

        let right_receipt = match right.append_and_flush(&entry, &canonical_record) {
            Ok(receipt) => receipt,
            Err(source) => {
                self.uncertain = true;
                return Err(Rpo0Error::ReplicaUnavailable {
                    replica: "right",
                    source,
                });
            }
        };
        if let Err(error) =
            validate_receipt("right", &right_replica_id, &right_receipt, &entry, checksum)
        {
            self.uncertain = true;
            return Err(error);
        }
        if left_receipt.replica_id == right_receipt.replica_id {
            self.uncertain = true;
            return Err(Rpo0Error::ReplicaIdentityCollision);
        }

        let state_root = next_state_root(self.state_root, &canonical_record);
        let acknowledgement = AcknowledgedWrite {
            operation_id: operation.id,
            commit_index: entry.commit_index,
            value: entry.value,
            state_root,
            replica_receipts: [left_receipt, right_receipt],
        };
        self.commit_index = entry.commit_index;
        self.value = entry.value;
        self.state_root = state_root;
        self.operations.insert(
            operation.id,
            AppliedOperation {
                increment: operation.increment,
                expected_commit_index: operation.expected_commit_index,
                acknowledgement: acknowledgement.clone(),
            },
        );
        Ok(acknowledgement)
    }
}

impl Default for ReplicatedCounter {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_receipt(
    replica: &'static str,
    expected_replica_id: &str,
    receipt: &DurableReceipt,
    entry: &WalEntry,
    checksum: u32,
) -> Result<(), Rpo0Error> {
    if receipt.replica_id != expected_replica_id
        || receipt.commit_index != entry.commit_index
        || receipt.record_checksum != checksum
    {
        return Err(Rpo0Error::InvalidDurabilityReceipt(replica));
    }
    Ok(())
}

fn recovery_receipt(replica_id: &str, commit_index: u64, record_checksum: u32) -> DurableReceipt {
    DurableReceipt {
        replica_id: replica_id.to_owned(),
        commit_index,
        record_checksum,
    }
}
