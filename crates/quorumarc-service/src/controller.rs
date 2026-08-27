use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use rustix::fs::OFlags;
use sha2::{Digest, Sha256};

use crate::management_journal::{JournalError, ManagementJournal, ManagementOutcome};
use crate::protocol::{AdmissionError, AuthenticatedRequestJournal};

/// One data-node role in a planned switch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SwitchRole {
    NodeA,
    NodeB,
}

/// Strict planned-switch transaction phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedSwitchStep {
    Prepare,
    CatchUp,
    HealthVerify,
    Drain,
    CloseOldEffects,
    Certify,
    PersistActivation,
    OpenNewEffects,
    Receipt,
    Complete,
    Halted,
}

/// Planned-switch refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlannedSwitchError {
    Ambiguous,
    SameRole,
}

/// Fail-closed planned switch state machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedSwitch {
    from: SwitchRole,
    to: SwitchRole,
    step: PlannedSwitchStep,
    effects_open: bool,
}

impl PlannedSwitch {
    /// Starts a switch with both external-effect paths considered closed.
    #[must_use]
    pub const fn new(from: SwitchRole, to: SwitchRole) -> Self {
        Self {
            from,
            to,
            step: PlannedSwitchStep::Prepare,
            effects_open: false,
        }
    }

    /// Current durable transaction step.
    #[must_use]
    pub const fn step(&self) -> PlannedSwitchStep {
        self.step
    }

    /// Whether the new effect path was reached.
    #[must_use]
    pub const fn effects_open(&self) -> bool {
        self.effects_open
    }

    /// Advances exactly one expected step; ambiguity halts closed.
    pub fn advance(&mut self, requested: PlannedSwitchStep) -> Result<(), PlannedSwitchError> {
        if self.from == self.to {
            self.halt();
            return Err(PlannedSwitchError::SameRole);
        }
        let Some(expected) = next_step(self.step) else {
            self.halt();
            return Err(PlannedSwitchError::Ambiguous);
        };
        if requested != expected {
            self.halt();
            return Err(PlannedSwitchError::Ambiguous);
        }
        self.step = if requested == PlannedSwitchStep::Receipt {
            PlannedSwitchStep::Complete
        } else {
            requested
        };
        if requested == PlannedSwitchStep::OpenNewEffects || requested == PlannedSwitchStep::Receipt
        {
            self.effects_open = true;
        }
        Ok(())
    }

    fn halt(&mut self) {
        self.effects_open = false;
        self.step = PlannedSwitchStep::Halted;
    }
}

const fn next_step(step: PlannedSwitchStep) -> Option<PlannedSwitchStep> {
    match step {
        PlannedSwitchStep::Prepare => Some(PlannedSwitchStep::CatchUp),
        PlannedSwitchStep::CatchUp => Some(PlannedSwitchStep::HealthVerify),
        PlannedSwitchStep::HealthVerify => Some(PlannedSwitchStep::Drain),
        PlannedSwitchStep::Drain => Some(PlannedSwitchStep::CloseOldEffects),
        PlannedSwitchStep::CloseOldEffects => Some(PlannedSwitchStep::Certify),
        PlannedSwitchStep::Certify => Some(PlannedSwitchStep::PersistActivation),
        PlannedSwitchStep::PersistActivation => Some(PlannedSwitchStep::OpenNewEffects),
        PlannedSwitchStep::OpenNewEffects => Some(PlannedSwitchStep::Receipt),
        PlannedSwitchStep::Receipt | PlannedSwitchStep::Complete | PlannedSwitchStep::Halted => {
            None
        }
    }
}

/// Restarts from a durable request journal without opening effects.
#[derive(Debug)]
pub struct DurableController {
    admission: AuthenticatedRequestJournal,
    switch: PlannedSwitch,
}

impl DurableController {
    pub fn open(
        directory: &Path,
        identity: [u8; 16],
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
        from: SwitchRole,
        to: SwitchRole,
    ) -> Result<Self, JournalError> {
        let journal = ManagementJournal::open(directory, identity)?;
        Ok(Self {
            admission: AuthenticatedRequestJournal::new(journal, node_id, key_id, verifying_key),
            switch: PlannedSwitch::new(from, to),
        })
    }

    pub fn accept(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        self.admission.admit(bytes)
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.admission.highest_sequence()
    }

    #[must_use]
    pub const fn effects_open(&self) -> bool {
        self.switch.effects_open()
    }
}

const PROGRESS_LEASE_MAGIC: &[u8; 8] = b"QARCLP01";
const PROGRESS_LEASE_DOMAIN: &[u8] = b"quorumarc/progress-lease/v1\0";
const PROGRESS_IDENTITY_LEN: usize = 16;
const PROGRESS_HEADER_LEN: usize = PROGRESS_LEASE_MAGIC.len() + PROGRESS_IDENTITY_LEN;
const PROGRESS_BODY_LEN: usize = 16;
const PROGRESS_CHECKSUM_LEN: usize = 32;
const PROGRESS_RECORD_LEN: usize = PROGRESS_BODY_LEN + PROGRESS_CHECKSUM_LEN;

/// Heartbeats cannot extend authority; only newly durable progress can.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProgressLeaseError {
    ProgressNotAdvanced,
    ClockOverflow,
    IdentityMismatch,
    Corrupt,
    Io,
}

/// Identity-bound lease expiry that survives restart without heartbeat renewal.
#[derive(Debug)]
pub struct DurableProgressLease {
    path: PathBuf,
    identity: [u8; PROGRESS_IDENTITY_LEN],
    progress_commit: u64,
    expires_at_ms: Option<u64>,
}

impl DurableProgressLease {
    pub fn open(
        directory: &Path,
        identity: [u8; PROGRESS_IDENTITY_LEN],
    ) -> Result<Self, ProgressLeaseError> {
        fs::create_dir_all(directory).map_err(|_error| ProgressLeaseError::Io)?;
        let path = directory.join("progress.lease");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(mut file) => {
                let mut header = [0_u8; PROGRESS_HEADER_LEN];
                header[..PROGRESS_LEASE_MAGIC.len()].copy_from_slice(PROGRESS_LEASE_MAGIC);
                header[PROGRESS_LEASE_MAGIC.len()..].copy_from_slice(&identity);
                file.write_all(&header)
                    .and_then(|()| file.sync_all())
                    .map_err(|_error| ProgressLeaseError::Io)?;
                File::open(directory)
                    .and_then(|parent| parent.sync_all())
                    .map_err(|_error| ProgressLeaseError::Io)?;
                Ok(Self {
                    path,
                    identity,
                    progress_commit: 0,
                    expires_at_ms: None,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata =
                    fs::symlink_metadata(&path).map_err(|_error| ProgressLeaseError::Io)?;
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(ProgressLeaseError::Corrupt);
                }
                let (recovered_identity, progress_commit, expires_at_ms) =
                    recover_progress_lease(&path)?;
                if recovered_identity != identity {
                    return Err(ProgressLeaseError::IdentityMismatch);
                }
                Ok(Self {
                    path,
                    identity,
                    progress_commit,
                    expires_at_ms,
                })
            }
            Err(_error) => Err(ProgressLeaseError::Io),
        }
    }

    #[must_use]
    pub const fn expires_at_ms(&self) -> Option<u64> {
        self.expires_at_ms
    }

    #[must_use]
    pub const fn highest_progress_commit(&self) -> u64 {
        self.progress_commit
    }

    #[must_use]
    pub const fn observe_heartbeat(&self, _now_ms: u64) -> Option<u64> {
        self.expires_at_ms
    }

    pub fn record_progress(
        &mut self,
        progress_commit: u64,
        now_ms: u64,
        duration_ms: u64,
    ) -> Result<u64, ProgressLeaseError> {
        if progress_commit == 0 || progress_commit <= self.progress_commit {
            return Err(ProgressLeaseError::ProgressNotAdvanced);
        }
        let expires_at_ms = now_ms
            .checked_add(duration_ms)
            .ok_or(ProgressLeaseError::ClockOverflow)?;
        if duration_ms == 0 {
            return Err(ProgressLeaseError::ProgressNotAdvanced);
        }
        let encoded = encode_progress_record(self.identity, progress_commit, expires_at_ms);
        let mut file = OpenOptions::new()
            .append(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&self.path)
            .map_err(|_error| ProgressLeaseError::Io)?;
        file.write_all(&encoded)
            .and_then(|()| file.sync_all())
            .map_err(|_error| ProgressLeaseError::Io)?;
        self.progress_commit = progress_commit;
        self.expires_at_ms = Some(expires_at_ms);
        Ok(expires_at_ms)
    }
}

const MAX_PROGRESS_LEASE_SIZE: u64 = 65_536;

fn recover_progress_lease(
    path: &Path,
) -> Result<([u8; PROGRESS_IDENTITY_LEN], u64, Option<u64>), ProgressLeaseError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_error| ProgressLeaseError::Io)?;
    let metadata = file.metadata().map_err(|_error| ProgressLeaseError::Io)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_PROGRESS_LEASE_SIZE
    {
        return Err(ProgressLeaseError::Corrupt);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_PROGRESS_LEASE_SIZE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| ProgressLeaseError::Io)?;
    if bytes.len() < PROGRESS_HEADER_LEN
        || bytes.len() > MAX_PROGRESS_LEASE_SIZE as usize
        || &bytes[..PROGRESS_LEASE_MAGIC.len()] != PROGRESS_LEASE_MAGIC
        || (bytes.len() - PROGRESS_HEADER_LEN) % PROGRESS_RECORD_LEN != 0
    {
        return Err(ProgressLeaseError::Corrupt);
    }
    let mut identity = [0_u8; PROGRESS_IDENTITY_LEN];
    identity.copy_from_slice(&bytes[PROGRESS_LEASE_MAGIC.len()..PROGRESS_HEADER_LEN]);
    let mut progress_commit = 0_u64;
    let mut expires_at_ms = None;
    for record in bytes[PROGRESS_HEADER_LEN..].chunks_exact(PROGRESS_RECORD_LEN) {
        let expected = progress_record_checksum(identity, &record[..PROGRESS_BODY_LEN]);
        if record[PROGRESS_BODY_LEN..] != expected {
            return Err(ProgressLeaseError::Corrupt);
        }
        let commit = u64::from_be_bytes(
            record[..8]
                .try_into()
                .map_err(|_error| ProgressLeaseError::Corrupt)?,
        );
        let expiry = u64::from_be_bytes(
            record[8..16]
                .try_into()
                .map_err(|_error| ProgressLeaseError::Corrupt)?,
        );
        if commit == 0 || commit <= progress_commit {
            return Err(ProgressLeaseError::Corrupt);
        }
        progress_commit = commit;
        expires_at_ms = Some(expiry);
    }
    Ok((identity, progress_commit, expires_at_ms))
}

fn encode_progress_record(
    identity: [u8; PROGRESS_IDENTITY_LEN],
    progress_commit: u64,
    expires_at_ms: u64,
) -> [u8; PROGRESS_RECORD_LEN] {
    let mut bytes = [0_u8; PROGRESS_RECORD_LEN];
    bytes[..8].copy_from_slice(&progress_commit.to_be_bytes());
    bytes[8..16].copy_from_slice(&expires_at_ms.to_be_bytes());
    let checksum = progress_record_checksum(identity, &bytes[..PROGRESS_BODY_LEN]);
    bytes[PROGRESS_BODY_LEN..].copy_from_slice(&checksum);
    bytes
}

fn progress_record_checksum(
    identity: [u8; PROGRESS_IDENTITY_LEN],
    body: &[u8],
) -> [u8; PROGRESS_CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(PROGRESS_LEASE_DOMAIN);
    hasher.update(identity);
    hasher.update(body);
    hasher.finalize().into()
}
