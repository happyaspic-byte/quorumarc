use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_store::{
    ActivationReceipt, AuthorityState, DurableAuthorityStore, FaultInjectingBackend, FaultMode,
    FaultOperation, FaultRule, FileBackend, LeaseBounds, PromotionRecord, StateRoot, StoreError,
    StorePaths, TransitionOutcome, VoteRecord,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const FIXED_SEEDS: [u64; 3] = [
    0x4d59_5df4_d0f3_3173,
    0x9e37_79b9_7f4a_7c15,
    0xd1b5_4a32_d192_ed03,
];
const ACKNOWLEDGED_ITERATIONS: u64 = 8;
const CORRUPTION_ITERATIONS: u64 = 8;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn create(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-store-campaign-{label}-{}-{sequence}",
            std::process::id()
        ));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

struct Deterministic(u64);

impl Deterministic {
    const fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn array_32(&mut self) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for byte in &mut output {
            *byte = self.next_u64().to_le_bytes()[0];
        }
        output
    }
}

struct FaultCase {
    label: &'static str,
    rule: FaultRule,
    rename_was_visible: bool,
}

fn recover_exact(
    directory: &Path,
    expected_generation: u64,
    expected_state: &AuthorityState,
) -> TestResult<DurableAuthorityStore<FileBackend>> {
    let recovered = DurableAuthorityStore::open_in(directory, FileBackend)?;
    assert_eq!(recovered.generation(), expected_generation);
    assert_eq!(recovered.state(), expected_state);
    Ok(recovered)
}

fn require_store_error<T>(result: Result<T, StoreError>, context: &str) -> TestResult<StoreError> {
    match result {
        Ok(_) => Err(io::Error::other(format!("{context} unexpectedly succeeded")).into()),
        Err(error) => Ok(error),
    }
}

fn require_corrupt_recovery(paths: StorePaths, context: &str) -> TestResult {
    match DurableAuthorityStore::open(paths, FileBackend) {
        Err(StoreError::Corrupt(_)) => Ok(()),
        Err(error) => Err(io::Error::other(format!(
            "{context} returned a non-corruption error: {error}"
        ))
        .into()),
        Ok(_) => Err(io::Error::other(format!("{context} unexpectedly recovered")).into()),
    }
}

#[test]
fn acknowledged_generations_recover_exactly_across_fixed_seed_campaign() -> TestResult {
    for (seed_index, seed) in FIXED_SEEDS.into_iter().enumerate() {
        let directory = TestDirectory::create(&format!("ack-{seed:016x}"))?;
        let mut random = Deterministic::new(seed);
        let mut store = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
        let mut expected_generation = 0_u64;
        let incarnation = random.next_u64() % 10_000 + 1;

        let incarnation_receipt = store.allocate_incarnation(incarnation)?;
        expected_generation += 1;
        assert_eq!(incarnation_receipt.generation(), expected_generation);
        assert_eq!(incarnation_receipt.outcome(), TransitionOutcome::Committed);
        let expected_state = store.state().clone();
        drop(store);
        store = recover_exact(directory.path(), expected_generation, &expected_state)?;

        for iteration in 0..ACKNOWLEDGED_ITERATIONS {
            let epoch = 1_000 + (seed_index as u64 * 100) + iteration;
            let digest = random.array_32();
            let signed_envelope_digest = random.array_32();
            let root = StateRoot::new(random.array_32());
            let vote = VoteRecord::new(epoch, "node-a", digest)?;

            let vote_receipt = store.record_vote(vote.clone())?;
            expected_generation += 1;
            assert_eq!(vote_receipt.generation(), expected_generation);
            assert_eq!(vote_receipt.outcome(), TransitionOutcome::Committed);
            let expected_state = store.state().clone();
            drop(store);
            store = recover_exact(directory.path(), expected_generation, &expected_state)?;

            let exact_retry = store.record_vote(vote)?;
            assert_eq!(exact_retry.generation(), expected_generation);
            assert_eq!(exact_retry.outcome(), TransitionOutcome::AlreadyDurable);

            let conflict = VoteRecord::new(epoch, "node-b", random.array_32())?;
            let conflict_error =
                require_store_error(store.record_vote(conflict), "same-epoch double vote")?;
            assert!(matches!(
                conflict_error,
                StoreError::DoubleVote { epoch: value } if value == epoch
            ));

            let stale = VoteRecord::new(epoch - 1, "node-a", random.array_32())?;
            let stale_error = require_store_error(store.record_vote(stale), "stale vote")?;
            assert!(matches!(
                stale_error,
                StoreError::StaleEpoch {
                    requested,
                    durable
                } if requested == epoch - 1 && durable == epoch
            ));
            assert_eq!(store.generation(), expected_generation);
            assert_eq!(store.state(), &expected_state);

            let lease_start = 100_000 + iteration * 1_000;
            let lease_end = lease_start + 500;
            let commit_index = iteration + 1;
            let promotion = PromotionRecord::new(
                epoch,
                digest,
                signed_envelope_digest,
                LeaseBounds::new(lease_start, lease_end)?,
                commit_index,
                root,
            )?;
            let promotion_receipt = store.record_promotion(promotion)?;
            expected_generation += 1;
            assert_eq!(promotion_receipt.generation(), expected_generation);
            assert_eq!(promotion_receipt.outcome(), TransitionOutcome::Committed);
            let expected_state = store.state().clone();
            drop(store);
            store = recover_exact(directory.path(), expected_generation, &expected_state)?;

            let activation = ActivationReceipt::new(
                epoch,
                "node-a",
                incarnation,
                signed_envelope_digest,
                lease_start + 1,
                lease_end,
            )?;
            let activation_receipt = store.record_activation(activation.clone())?;
            expected_generation += 1;
            assert_eq!(activation_receipt.generation(), expected_generation);
            assert_eq!(activation_receipt.outcome(), TransitionOutcome::Committed);
            let expected_state = store.state().clone();
            drop(store);
            store = recover_exact(directory.path(), expected_generation, &expected_state)?;

            let activation_retry = store.record_activation(activation)?;
            assert_eq!(activation_retry.generation(), expected_generation);
            assert_eq!(
                activation_retry.outcome(),
                TransitionOutcome::AlreadyDurable
            );
        }
    }
    Ok(())
}

#[test]
fn failed_or_ambiguous_activation_persist_never_issues_authority_receipt() -> TestResult {
    for seed in FIXED_SEEDS {
        let mut random = Deterministic::new(seed);
        let partial_write_bytes = (random.next_u64() % 31 + 1) as usize;
        let fault_cases = [
            FaultCase {
                label: "prepare-remove",
                rule: FaultRule {
                    operation: FaultOperation::Remove,
                    // Opening the store performs occurrence one. The persist
                    // preparation is the second remove operation.
                    occurrence: 2,
                    mode: FaultMode::Error(io::ErrorKind::Other),
                },
                rename_was_visible: false,
            },
            FaultCase {
                label: "write",
                rule: FaultRule {
                    operation: FaultOperation::Write,
                    occurrence: 1,
                    mode: FaultMode::Error(io::ErrorKind::Other),
                },
                rename_was_visible: false,
            },
            FaultCase {
                label: "partial-write",
                rule: FaultRule {
                    operation: FaultOperation::Write,
                    occurrence: 1,
                    mode: FaultMode::PartialWrite {
                        bytes: partial_write_bytes,
                        error_kind: io::ErrorKind::WriteZero,
                    },
                },
                rename_was_visible: false,
            },
            FaultCase {
                label: "file-sync",
                rule: FaultRule {
                    operation: FaultOperation::SyncFile,
                    occurrence: 1,
                    mode: FaultMode::Error(io::ErrorKind::Other),
                },
                rename_was_visible: false,
            },
            FaultCase {
                label: "rename",
                rule: FaultRule {
                    operation: FaultOperation::Rename,
                    occurrence: 1,
                    mode: FaultMode::Error(io::ErrorKind::Other),
                },
                rename_was_visible: false,
            },
            FaultCase {
                label: "directory-sync",
                rule: FaultRule {
                    operation: FaultOperation::SyncDirectory,
                    occurrence: 1,
                    mode: FaultMode::Error(io::ErrorKind::Other),
                },
                rename_was_visible: true,
            },
        ];

        for fault_case in fault_cases {
            let directory =
                TestDirectory::create(&format!("fault-{}-{seed:016x}", fault_case.label))?;
            let epoch = random.next_u64() % 10_000 + 2;
            let incarnation = random.next_u64() % 10_000 + 1;
            let digest = random.array_32();
            let signed_envelope_digest = random.array_32();
            let state_root = StateRoot::new(random.array_32());
            let lease_start = random.next_u64() % 1_000_000 + 1_000;
            let lease_end = lease_start + 1_000;
            let activation = ActivationReceipt::new(
                epoch,
                "node-a",
                incarnation,
                signed_envelope_digest,
                lease_start + 1,
                lease_end,
            )?;

            let (before_generation, before_state) = {
                let mut bootstrap = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
                bootstrap.allocate_incarnation(incarnation)?;
                bootstrap.record_vote(VoteRecord::new(epoch, "node-a", digest)?)?;
                bootstrap.record_promotion(PromotionRecord::new(
                    epoch,
                    digest,
                    signed_envelope_digest,
                    LeaseBounds::new(lease_start, lease_end)?,
                    41,
                    state_root,
                )?)?;
                (bootstrap.generation(), bootstrap.state().clone())
            };
            assert!(before_state.activation_receipt().is_none());

            let backend = FaultInjectingBackend::new(FileBackend, vec![fault_case.rule]);
            let mut faulted = DurableAuthorityStore::open_in(directory.path(), backend)?;
            let failed = require_store_error(
                faulted.record_activation(activation.clone()),
                "fault-injected activation persist",
            )?;
            assert!(matches!(failed, StoreError::Io { .. }));
            assert!(faulted.is_poisoned());
            assert_eq!(faulted.generation(), before_generation);
            assert_eq!(faulted.state(), &before_state);
            assert!(faulted.state().activation_receipt().is_none());

            let poisoned_retry = require_store_error(
                faulted.record_activation(activation.clone()),
                "write through poisoned store",
            )?;
            assert!(matches!(poisoned_retry, StoreError::Poisoned));
            drop(faulted);

            // A directory-sync error happens after rename. Recovery may see
            // that complete new frame, but the failed call emitted no
            // DurabilityReceipt. The caller must retry the same operation and
            // obtain a receipt before using durability as an authority input.
            let mut recovered = DurableAuthorityStore::open_in(directory.path(), FileBackend)?;
            if fault_case.rename_was_visible {
                assert_eq!(recovered.generation(), before_generation + 1);
                assert_eq!(recovered.state().activation_receipt(), Some(&activation));
            } else {
                assert_eq!(recovered.generation(), before_generation);
                assert_eq!(recovered.state(), &before_state);
                assert!(recovered.state().activation_receipt().is_none());
            }

            let retry_receipt = recovered.record_activation(activation.clone())?;
            assert_eq!(retry_receipt.generation(), before_generation + 1);
            if fault_case.rename_was_visible {
                assert_eq!(retry_receipt.outcome(), TransitionOutcome::AlreadyDurable);
            } else {
                assert_eq!(retry_receipt.outcome(), TransitionOutcome::Committed);
            }
            assert_eq!(recovered.state().activation_receipt(), Some(&activation));
            let final_state = recovered.state().clone();
            drop(recovered);

            let mut recovered =
                recover_exact(directory.path(), before_generation + 1, &final_state)?;
            let exact_vote = VoteRecord::new(epoch, "node-a", digest)?;
            let vote_retry = recovered.record_vote(exact_vote)?;
            assert_eq!(vote_retry.outcome(), TransitionOutcome::AlreadyDurable);
            assert_eq!(vote_retry.generation(), before_generation + 1);

            let double_vote = VoteRecord::new(epoch, "node-b", random.array_32())?;
            let double_vote_error =
                require_store_error(recovered.record_vote(double_vote), "recovered double vote")?;
            assert!(matches!(
                double_vote_error,
                StoreError::DoubleVote { epoch: value } if value == epoch
            ));

            let stale_vote = VoteRecord::new(epoch - 1, "node-a", random.array_32())?;
            let stale_vote_error =
                require_store_error(recovered.record_vote(stale_vote), "recovered stale vote")?;
            assert!(matches!(
                stale_vote_error,
                StoreError::StaleEpoch {
                    requested,
                    durable
                } if requested == epoch - 1 && durable == epoch
            ));
            assert_eq!(recovered.generation(), before_generation + 1);
            assert_eq!(recovered.state(), &final_state);
        }
    }
    Ok(())
}

#[test]
fn corrupt_and_truncated_committed_frames_fail_closed_across_fixed_seeds() -> TestResult {
    for seed in FIXED_SEEDS {
        let source_directory = TestDirectory::create(&format!("corruption-source-{seed:016x}"))?;
        let source_paths = StorePaths::new(source_directory.path());
        let mut random = Deterministic::new(seed);
        let epoch = random.next_u64() % 10_000 + 1;
        let incarnation = random.next_u64() % 10_000 + 1;
        let digest = random.array_32();
        let signed_envelope_digest = random.array_32();
        let state_root = StateRoot::new(random.array_32());
        let lease_start = random.next_u64() % 1_000_000 + 1_000;
        let lease_end = lease_start + 1_000;
        {
            let mut source = DurableAuthorityStore::open(source_paths.clone(), FileBackend)?;
            source.allocate_incarnation(incarnation)?;
            source.record_vote(VoteRecord::new(epoch, "node-a", digest)?)?;
            source.record_promotion(PromotionRecord::new(
                epoch,
                digest,
                signed_envelope_digest,
                LeaseBounds::new(lease_start, lease_end)?,
                73,
                state_root,
            )?)?;
            source.record_activation(ActivationReceipt::new(
                epoch,
                "node-a",
                incarnation,
                signed_envelope_digest,
                lease_start + 1,
                lease_end,
            )?)?;
        }
        let complete_frame = fs::read(source_paths.committed())?;
        let truncation_span = complete_frame
            .len()
            .checked_sub(1)
            .ok_or_else(|| io::Error::other("committed frame was unexpectedly empty"))?;
        let protected_payload_span = complete_frame
            .len()
            .checked_sub(36)
            .ok_or_else(|| io::Error::other("committed frame had no protected payload"))?;

        for iteration in 0..CORRUPTION_ITERATIONS {
            let truncated_directory =
                TestDirectory::create(&format!("truncated-{seed:016x}-{iteration}"))?;
            let truncated_paths = StorePaths::new(truncated_directory.path());
            let retained = random.next_u64() as usize % truncation_span + 1;
            fs::write(truncated_paths.committed(), &complete_frame[..retained])?;
            require_corrupt_recovery(truncated_paths, "truncated committed frame")?;

            let corrupt_directory =
                TestDirectory::create(&format!("corrupt-{seed:016x}-{iteration}"))?;
            let corrupt_paths = StorePaths::new(corrupt_directory.path());
            let mut corrupt_frame = complete_frame.clone();
            let offset = 24 + random.next_u64() as usize % protected_payload_span;
            let bit = 1_u8 << (random.next_u64() % 8);
            let byte = corrupt_frame
                .get_mut(offset)
                .ok_or_else(|| io::Error::other("selected corruption offset was out of range"))?;
            *byte ^= bit;
            fs::write(corrupt_paths.committed(), corrupt_frame)?;
            require_corrupt_recovery(corrupt_paths, "corrupt committed frame")?;
        }
    }
    Ok(())
}
