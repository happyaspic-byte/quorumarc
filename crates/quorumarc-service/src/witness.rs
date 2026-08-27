use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use quorumarc_runtime::{VoteReasonCode, WitnessOpenError, WitnessPolicy, WitnessVoteActor};
use quorumarc_store::{FileBackend, StoreIdentity};
use quorumarc_wire::{
    CanonicalId, MessageId, PROTOCOL_VERSION, ProductionSignedVote, QuorumBinding,
};
use rustix::fs::{FlockOperation, OFlags, flock};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use sha2::{Digest, Sha256};

use crate::management_journal::{JournalError, ManagementJournal, ManagementOutcome};
use crate::protocol::{
    AdmissionError, AuthenticatedRequestJournal, ProductionFrame, ProductionFrameError,
    ProductionFrameKind, ProductionVotePayload,
};
use crate::signal::ShutdownToken;
use crate::tls::MtlsServerConfig;

/// Static three-member Witness membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessMembership {
    node_a_id: String,
    node_a: SocketAddr,
    node_b_id: String,
    node_b: SocketAddr,
    witness_id: String,
    witness: SocketAddr,
}

/// Typed membership refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessMembershipError {
    SharedHost,
    SharedFailureDomain,
    InvalidMember,
    ReservedWitnessHost,
    DuplicateMember,
}

impl WitnessMembership {
    /// Accepts exactly two data nodes and one independent Witness.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_a_id: impl Into<String>,
        node_a: SocketAddr,
        node_a_domain: &str,
        node_b_id: impl Into<String>,
        node_b: SocketAddr,
        node_b_domain: &str,
        witness_id: impl Into<String>,
        witness: SocketAddr,
        witness_domain: &str,
    ) -> Result<Self, WitnessMembershipError> {
        let node_a_id = node_a_id.into();
        let node_b_id = node_b_id.into();
        let witness_id = witness_id.into();
        if node_a_id.is_empty() || node_b_id.is_empty() || witness_id.is_empty() {
            return Err(WitnessMembershipError::InvalidMember);
        }
        if node_a_id == node_b_id || node_a_id == witness_id || node_b_id == witness_id {
            return Err(WitnessMembershipError::DuplicateMember);
        }
        if same_host(node_a.ip(), node_b.ip())
            || same_host(node_a.ip(), witness.ip())
            || same_host(node_b.ip(), witness.ip())
        {
            return Err(WitnessMembershipError::SharedHost);
        }
        if canonical_ip(witness.ip()) == IpAddr::V4(Ipv4Addr::new(172, 30, 1, 84)) {
            return Err(WitnessMembershipError::ReservedWitnessHost);
        }
        if node_a_domain == witness_domain
            || node_b_domain == witness_domain
            || node_a_domain == node_b_domain
        {
            return Err(WitnessMembershipError::SharedFailureDomain);
        }
        Ok(Self {
            node_a_id,
            node_a,
            node_b_id,
            node_b,
            witness_id,
            witness,
        })
    }

    #[must_use]
    pub fn node_a_id(&self) -> &str {
        &self.node_a_id
    }

    #[must_use]
    pub fn node_b_id(&self) -> &str {
        &self.node_b_id
    }

    #[must_use]
    pub fn witness_id(&self) -> &str {
        &self.witness_id
    }

    /// Independent Witness listen address.
    #[must_use]
    pub const fn witness_address(&self) -> SocketAddr {
        self.witness
    }

    /// Node A listen address.
    #[must_use]
    pub const fn node_a_address(&self) -> SocketAddr {
        self.node_a
    }

    /// Node B listen address.
    #[must_use]
    pub const fn node_b_address(&self) -> SocketAddr {
        self.node_b
    }
}

fn same_host(left: IpAddr, right: IpAddr) -> bool {
    canonical_ip(left) == canonical_ip(right)
}

fn canonical_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
    }
}

const WITNESS_IO_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_WITNESS_CONNECTIONS: usize = 32;
const MAX_WITNESS_FRAME: usize =
    8 + 2 + 1 + 4 * (1 + 128) + 16 + 8 + 8 + 8 + 8 + 32 + 4 + 65_536 + 64;
const VOTE_REPLY_MAGIC: &[u8; 8] = b"QARCVR03";
const VOTE_REPLY_ATTESTATION_DOMAIN: &[u8] = b"quorumarc/production-vote-reply/ed25519/v3\0";
const SIGNER_IDENTITY_MAGIC: &[u8; 8] = b"QARCSI01";

#[derive(Clone, Debug)]
pub struct CandidateCredential {
    node_id: CanonicalId,
    key_id: CanonicalId,
    verifying_key: VerifyingKey,
}

impl CandidateCredential {
    pub fn new(
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, ProductionFrameError> {
        Ok(Self {
            node_id: CanonicalId::new(node_id.into())
                .map_err(|_error| ProductionFrameError::Malformed)?,
            key_id: CanonicalId::new(key_id.into())
                .map_err(|_error| ProductionFrameError::Malformed)?,
            verifying_key,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionVoteReply {
    cluster_id: String,
    witness_id: CanonicalId,
    key_id: CanonicalId,
    binding: QuorumBinding,
    code: VoteReasonCode,
    signed_vote: Option<ProductionSignedVote>,
    durable_generation: Option<u64>,
    attestation: [u8; 64],
}

impl ProductionVoteReply {
    #[must_use]
    pub fn cluster_id(&self) -> &str {
        &self.cluster_id
    }

    pub fn verify_attestation(
        &self,
        expected_cluster_id: &str,
        key: &VerifyingKey,
    ) -> Result<(), ProductionVoteError> {
        if self.cluster_id != expected_cluster_id {
            return Err(ProductionVoteError::AuthenticationFailed);
        }
        let statement = self.encode_statement()?;
        key.verify_strict(
            &vote_reply_attestation_preimage(&statement),
            &Signature::from_bytes(&self.attestation),
        )
        .map_err(|_error| ProductionVoteError::AuthenticationFailed)
    }

    #[must_use]
    pub const fn binding(&self) -> &QuorumBinding {
        &self.binding
    }

    #[must_use]
    pub const fn code(&self) -> VoteReasonCode {
        self.code
    }

    #[must_use]
    pub const fn signed_vote(&self) -> Option<&ProductionSignedVote> {
        self.signed_vote.as_ref()
    }

    #[must_use]
    pub const fn durable_generation(&self) -> Option<u64> {
        self.durable_generation
    }

    #[must_use]
    pub const fn is_granted(&self) -> bool {
        self.code.is_granted()
    }

    pub fn encode(&self) -> Result<Vec<u8>, ProductionVoteError> {
        let mut bytes = self.encode_statement()?;
        bytes.extend_from_slice(&self.attestation);
        Ok(bytes)
    }

    fn encode_statement(&self) -> Result<Vec<u8>, ProductionVoteError> {
        let binding = self
            .binding
            .to_canonical_bytes()
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let vote = self
            .signed_vote
            .as_ref()
            .map(ProductionSignedVote::to_canonical_bytes)
            .transpose()
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let cluster_len = u16::try_from(self.cluster_id.len())
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let witness_len = u16::try_from(self.witness_id.as_str().len())
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let key_len = u16::try_from(self.key_id.as_str().len())
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let binding_len =
            u32::try_from(binding.len()).map_err(|_error| ProductionVoteError::Malformed)?;
        let vote_len = u32::try_from(vote.as_ref().map_or(0, Vec::len))
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(VOTE_REPLY_MAGIC);
        bytes.extend_from_slice(&cluster_len.to_be_bytes());
        bytes.extend_from_slice(self.cluster_id.as_bytes());
        bytes.extend_from_slice(&witness_len.to_be_bytes());
        bytes.extend_from_slice(self.witness_id.as_str().as_bytes());
        bytes.extend_from_slice(&key_len.to_be_bytes());
        bytes.extend_from_slice(self.key_id.as_str().as_bytes());
        bytes.push(vote_reason_tag(self.code));
        bytes.extend_from_slice(&self.durable_generation.unwrap_or(0).to_be_bytes());
        bytes.extend_from_slice(&binding_len.to_be_bytes());
        bytes.extend_from_slice(&binding);
        bytes.extend_from_slice(&vote_len.to_be_bytes());
        if let Some(vote) = vote {
            bytes.extend_from_slice(&vote);
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProductionVoteError> {
        let mut cursor = 0_usize;
        if vote_reply_take(bytes, &mut cursor, VOTE_REPLY_MAGIC.len())? != VOTE_REPLY_MAGIC {
            return Err(ProductionVoteError::Malformed);
        }
        let cluster_id = vote_reply_read_id(bytes, &mut cursor)?;
        let witness_id = CanonicalId::new(vote_reply_read_id(bytes, &mut cursor)?)
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let key_id = CanonicalId::new(vote_reply_read_id(bytes, &mut cursor)?)
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let code = vote_reason_from_tag(vote_reply_take(bytes, &mut cursor, 1)?[0])?;
        let durable_generation = u64::from_be_bytes(
            vote_reply_take(bytes, &mut cursor, 8)?
                .try_into()
                .map_err(|_error| ProductionVoteError::Malformed)?,
        );
        let binding_len = u32::from_be_bytes(
            vote_reply_take(bytes, &mut cursor, 4)?
                .try_into()
                .map_err(|_error| ProductionVoteError::Malformed)?,
        ) as usize;
        let binding =
            QuorumBinding::from_canonical_bytes(vote_reply_take(bytes, &mut cursor, binding_len)?)
                .map_err(|_error| ProductionVoteError::Malformed)?;
        let vote_len = u32::from_be_bytes(
            vote_reply_take(bytes, &mut cursor, 4)?
                .try_into()
                .map_err(|_error| ProductionVoteError::Malformed)?,
        ) as usize;
        let signed_vote = if vote_len == 0 {
            None
        } else {
            Some(
                ProductionSignedVote::from_canonical_bytes(vote_reply_take(
                    bytes,
                    &mut cursor,
                    vote_len,
                )?)
                .map_err(|_error| ProductionVoteError::Malformed)?,
            )
        };
        let attestation: [u8; 64] = vote_reply_take(bytes, &mut cursor, 64)?
            .try_into()
            .map_err(|_error| ProductionVoteError::Malformed)?;
        if cursor != bytes.len()
            || code.is_granted() != signed_vote.is_some()
            || code.is_granted() != (durable_generation != 0)
            || signed_vote.as_ref().is_some_and(|vote| {
                vote.cluster_id().as_str() != cluster_id
                    || vote.voter_id() != &witness_id
                    || vote.key_id() != &key_id
            })
        {
            return Err(ProductionVoteError::Malformed);
        }
        Ok(Self {
            cluster_id,
            witness_id,
            key_id,
            binding,
            code,
            signed_vote,
            durable_generation: (durable_generation != 0).then_some(durable_generation),
            attestation,
        })
    }
}

fn vote_reason_tag(code: VoteReasonCode) -> u8 {
    match code {
        VoteReasonCode::GrantedDurablyRecorded => 1,
        VoteReasonCode::GrantedAlreadyDurable => 2,
        VoteReasonCode::RefusedMalformedBinding => 3,
        VoteReasonCode::RefusedWorkloadMismatch => 4,
        VoteReasonCode::RefusedPolicyMismatch => 5,
        VoteReasonCode::RefusedCandidateNotAllowed => 6,
        VoteReasonCode::RefusedLeaseTooLong => 7,
        VoteReasonCode::RefusedStaleEpoch => 8,
        VoteReasonCode::RefusedConflictSameEpoch => 9,
        VoteReasonCode::RefusedEpochAlreadyAccepted => 10,
        VoteReasonCode::RefusedStorePoisoned => 11,
        VoteReasonCode::RefusedDurabilityIo => 12,
        VoteReasonCode::RefusedStoreInvariant => 13,
        VoteReasonCode::RefusedGenerationExhausted => 14,
        VoteReasonCode::RefusedSigningFailure => 15,
    }
}

fn vote_reason_from_tag(tag: u8) -> Result<VoteReasonCode, ProductionVoteError> {
    match tag {
        1 => Ok(VoteReasonCode::GrantedDurablyRecorded),
        2 => Ok(VoteReasonCode::GrantedAlreadyDurable),
        3 => Ok(VoteReasonCode::RefusedMalformedBinding),
        4 => Ok(VoteReasonCode::RefusedWorkloadMismatch),
        5 => Ok(VoteReasonCode::RefusedPolicyMismatch),
        6 => Ok(VoteReasonCode::RefusedCandidateNotAllowed),
        7 => Ok(VoteReasonCode::RefusedLeaseTooLong),
        8 => Ok(VoteReasonCode::RefusedStaleEpoch),
        9 => Ok(VoteReasonCode::RefusedConflictSameEpoch),
        10 => Ok(VoteReasonCode::RefusedEpochAlreadyAccepted),
        11 => Ok(VoteReasonCode::RefusedStorePoisoned),
        12 => Ok(VoteReasonCode::RefusedDurabilityIo),
        13 => Ok(VoteReasonCode::RefusedStoreInvariant),
        14 => Ok(VoteReasonCode::RefusedGenerationExhausted),
        15 => Ok(VoteReasonCode::RefusedSigningFailure),
        _ => Err(ProductionVoteError::Malformed),
    }
}

fn vote_reply_read_id(bytes: &[u8], cursor: &mut usize) -> Result<String, ProductionVoteError> {
    let len = usize::from(u16::from_be_bytes(
        vote_reply_take(bytes, cursor, 2)?
            .try_into()
            .map_err(|_error| ProductionVoteError::Malformed)?,
    ));
    if len == 0 || len > 128 {
        return Err(ProductionVoteError::Malformed);
    }
    let text = std::str::from_utf8(vote_reply_take(bytes, cursor, len)?)
        .map_err(|_error| ProductionVoteError::Malformed)?;
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ProductionVoteError::Malformed);
    }
    Ok(text.to_owned())
}

fn vote_reply_attestation_preimage(statement: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(VOTE_REPLY_ATTESTATION_DOMAIN.len() + statement.len());
    preimage.extend_from_slice(VOTE_REPLY_ATTESTATION_DOMAIN);
    preimage.extend_from_slice(statement);
    preimage
}

fn vote_reply_take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProductionVoteError> {
    let end = cursor
        .checked_add(len)
        .ok_or(ProductionVoteError::Malformed)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(ProductionVoteError::Malformed)?;
    *cursor = end;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProductionVoteError {
    Malformed,
    AuthenticationFailed,
    EpochJump,
    IncarnationRollback,
    IncarnationIo,
    UnsupportedRuntime,
}

#[derive(Debug)]
pub enum ProductionWitnessOpenError {
    OwnerLockRefused,
    SignerIdentityMismatch,
    CredentialKeyConflict,
    IncarnationJournal,
    Actor(WitnessOpenError),
}

impl From<WitnessOpenError> for ProductionWitnessOpenError {
    fn from(error: WitnessOpenError) -> Self {
        Self::Actor(error)
    }
}

struct WitnessOwnerLock {
    _file: File,
}

struct CandidateIncarnationJournal {
    directory: PathBuf,
    path: PathBuf,
    highest: BTreeMap<String, u64>,
    poisoned: bool,
}

impl CandidateIncarnationJournal {
    fn open(directory: &Path) -> Result<Self, ProductionWitnessOpenError> {
        const MAGIC: &[u8; 8] = b"QARCIC01";
        let path = directory.join("candidate-incarnations.journal");
        let temporary = directory.join("candidate-incarnations.journal.tmp");
        match fs::remove_file(&temporary) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_error) => return Err(ProductionWitnessOpenError::IncarnationJournal),
        }
        let highest = match OpenOptions::new()
            .read(true)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
        {
            Ok(mut file) => {
                let metadata = file
                    .metadata()
                    .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?;
                if !metadata.is_file()
                    || metadata.permissions().mode() & 0o077 != 0
                    || metadata.len() > 1_048_576
                {
                    return Err(ProductionWitnessOpenError::IncarnationJournal);
                }
                let mut bytes = Vec::new();
                (&mut file)
                    .take(1_048_577)
                    .read_to_end(&mut bytes)
                    .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?;
                if bytes.len() < MAGIC.len() || &bytes[..MAGIC.len()] != MAGIC {
                    return Err(ProductionWitnessOpenError::IncarnationJournal);
                }
                recover_incarnations(&bytes[MAGIC.len()..])?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(_error) => return Err(ProductionWitnessOpenError::IncarnationJournal),
        };
        let journal = Self {
            directory: directory.to_owned(),
            path,
            highest,
            poisoned: false,
        };
        if !journal.path.exists() {
            journal
                .persist(&journal.highest.clone())
                .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?;
        }
        Ok(journal)
    }

    fn record(
        &mut self,
        candidate: &CanonicalId,
        incarnation: u64,
    ) -> Result<(), ProductionVoteError> {
        if self.poisoned {
            return Err(ProductionVoteError::IncarnationIo);
        }
        let current = self.highest.get(candidate.as_str()).copied().unwrap_or(0);
        if incarnation < current {
            return Err(ProductionVoteError::IncarnationRollback);
        }
        if incarnation == current {
            return Ok(());
        }
        let mut next = self.highest.clone();
        next.insert(candidate.as_str().to_owned(), incarnation);
        if self.persist(&next).is_err() {
            self.poisoned = true;
            return Err(ProductionVoteError::IncarnationIo);
        }
        self.highest = next;
        Ok(())
    }

    fn persist(&self, highest: &BTreeMap<String, u64>) -> std::io::Result<()> {
        let temporary = self.directory.join("candidate-incarnations.journal.tmp");
        let mut bytes = b"QARCIC01".to_vec();
        for (candidate, incarnation) in highest {
            let candidate_len = u8::try_from(candidate.len()).map_err(|_error| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "candidate id too long")
            })?;
            let mut record = vec![candidate_len];
            record.extend_from_slice(candidate.as_bytes());
            record.extend_from_slice(&incarnation.to_be_bytes());
            let mut hasher = Sha256::new();
            hasher.update(b"quorumarc/candidate-incarnation/v1\0");
            hasher.update(&record);
            record.extend_from_slice(&hasher.finalize());
            bytes.extend_from_slice(&record);
        }
        if bytes.len() > 1_048_576 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "candidate incarnation state exceeds capacity",
            ));
        }
        let _ = fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(OFlags::NOFOLLOW.bits() as i32)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, &self.path)?;
        File::open(&self.directory)?.sync_all()
    }
}

fn recover_incarnations(bytes: &[u8]) -> Result<BTreeMap<String, u64>, ProductionWitnessOpenError> {
    let mut cursor = 0_usize;
    let mut highest = BTreeMap::new();
    while cursor < bytes.len() {
        let len = usize::from(
            *bytes
                .get(cursor)
                .ok_or(ProductionWitnessOpenError::IncarnationJournal)?,
        );
        cursor = cursor.saturating_add(1);
        if len == 0 || len > 128 {
            return Err(ProductionWitnessOpenError::IncarnationJournal);
        }
        let body_end = cursor
            .checked_add(len)
            .and_then(|value| value.checked_add(8))
            .ok_or(ProductionWitnessOpenError::IncarnationJournal)?;
        let checksum_end = body_end
            .checked_add(32)
            .ok_or(ProductionWitnessOpenError::IncarnationJournal)?;
        let body = bytes
            .get(cursor.saturating_sub(1)..body_end)
            .ok_or(ProductionWitnessOpenError::IncarnationJournal)?;
        let checksum = bytes
            .get(body_end..checksum_end)
            .ok_or(ProductionWitnessOpenError::IncarnationJournal)?;
        let candidate = std::str::from_utf8(
            bytes
                .get(cursor..cursor + len)
                .ok_or(ProductionWitnessOpenError::IncarnationJournal)?,
        )
        .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?;
        CanonicalId::new(candidate)
            .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?;
        let incarnation = u64::from_be_bytes(
            bytes
                .get(cursor + len..body_end)
                .ok_or(ProductionWitnessOpenError::IncarnationJournal)?
                .try_into()
                .map_err(|_error| ProductionWitnessOpenError::IncarnationJournal)?,
        );
        let mut hasher = Sha256::new();
        hasher.update(b"quorumarc/candidate-incarnation/v1\0");
        hasher.update(body);
        if checksum != hasher.finalize().as_slice() || incarnation == 0 {
            return Err(ProductionWitnessOpenError::IncarnationJournal);
        }
        let current = highest.get(candidate).copied().unwrap_or(0);
        if incarnation <= current {
            return Err(ProductionWitnessOpenError::IncarnationJournal);
        }
        highest.insert(candidate.to_owned(), incarnation);
        cursor = checksum_end;
    }
    Ok(highest)
}

struct ProductionVoteRuntimeState {
    _owner_lock: WitnessOwnerLock,
    incarnations: CandidateIncarnationJournal,
    cluster_id: String,
    witness_id: CanonicalId,
    key_id: CanonicalId,
    signing_key: SigningKey,
    credentials: Vec<CandidateCredential>,
    actor: WitnessVoteActor<FileBackend>,
}

enum RuntimeMode {
    Management(Box<AuthenticatedRequestJournal>),
    Vote(Box<ProductionVoteRuntimeState>),
}

impl std::fmt::Debug for RuntimeMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Management(_) => formatter.write_str("Management"),
            Self::Vote(_) => formatter.write_str("Vote"),
        }
    }
}

/// Independent Witness that records authenticated votes without opening effects.
#[derive(Debug)]
pub struct ProductionWitnessRuntime {
    mode: RuntimeMode,
}

impl ProductionWitnessRuntime {
    pub fn open(
        directory: &Path,
        identity: [u8; 16],
        cluster_id: impl Into<String>,
        workload_id: impl Into<String>,
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, JournalError> {
        let journal = ManagementJournal::open(directory, identity)?;
        Ok(Self {
            mode: RuntimeMode::Management(Box::new(AuthenticatedRequestJournal::new(
                journal,
                cluster_id,
                workload_id,
                node_id,
                key_id,
                verifying_key,
            ))),
        })
    }

    pub fn open_vote_actor(
        directory: &Path,
        store_identity: StoreIdentity,
        policy: WitnessPolicy,
        signing_key: SigningKey,
        credentials: impl IntoIterator<Item = CandidateCredential>,
    ) -> Result<Self, ProductionWitnessOpenError> {
        let credentials = credentials.into_iter().collect::<Vec<_>>();
        let witness_key = signing_key.verifying_key();
        let mut credential_keys = BTreeSet::new();
        if credentials.iter().any(|credential| {
            credential.verifying_key == witness_key
                || !credential_keys.insert(credential.verifying_key.to_bytes())
        }) {
            return Err(ProductionWitnessOpenError::CredentialKeyConflict);
        }
        let owner_lock = acquire_witness_owner_lock(directory)?;
        let incarnations = CandidateIncarnationJournal::open(directory)?;
        let cluster_id = store_identity.cluster_id().to_owned();
        let witness_id = policy.witness_id().clone();
        let key_id = policy.key_id().clone();
        let actor = WitnessVoteActor::open(
            policy,
            signing_key.clone(),
            directory,
            store_identity,
            FileBackend,
        )?;
        pin_witness_signer_identity(
            directory,
            &witness_id,
            &key_id,
            &signing_key.verifying_key(),
        )?;
        Ok(Self {
            mode: RuntimeMode::Vote(Box::new(ProductionVoteRuntimeState {
                _owner_lock: owner_lock,
                incarnations,
                cluster_id,
                witness_id,
                key_id,
                signing_key,
                credentials,
                actor,
            })),
        })
    }

    pub fn admit_vote(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        match &mut self.mode {
            RuntimeMode::Management(admission) => admission.admit(bytes),
            RuntimeMode::Vote(_) => Err(AdmissionError::Malformed),
        }
    }

    pub fn handle_vote(
        &mut self,
        bytes: &[u8],
    ) -> Result<ProductionVoteReply, ProductionVoteError> {
        let RuntimeMode::Vote(state) = &mut self.mode else {
            return Err(ProductionVoteError::UnsupportedRuntime);
        };
        let ProductionVoteRuntimeState {
            incarnations,
            cluster_id,
            witness_id,
            key_id,
            signing_key,
            credentials,
            actor,
            ..
        } = state.as_mut();
        let frame = ProductionFrame::decode(bytes).map_err(map_vote_frame_error)?;
        if frame.kind() != ProductionFrameKind::Request {
            return Err(ProductionVoteError::Malformed);
        }
        let request = frame.request();
        if request.cluster_id != *cluster_id {
            return Err(ProductionVoteError::AuthenticationFailed);
        }
        let credential = credentials
            .iter()
            .find(|credential| {
                credential.node_id.as_str() == request.node_id
                    && credential.key_id.as_str() == request.key_id
            })
            .ok_or(ProductionVoteError::AuthenticationFailed)?;
        frame
            .verify(&credential.verifying_key)
            .map_err(map_vote_frame_error)?;
        let payload = ProductionVotePayload::decode(&request.payload)
            .map_err(|_error| ProductionVoteError::Malformed)?;
        let binding = QuorumBinding {
            protocol_version: PROTOCOL_VERSION,
            message_id: MessageId::new(request.request_id),
            workload_id: CanonicalId::new(request.workload_id.clone())
                .map_err(|_error| ProductionVoteError::Malformed)?,
            candidate_node_id: credential.node_id.clone(),
            candidate_incarnation: request.incarnation,
            epoch: request.epoch,
            policy_hash: request.policy_hash,
            required_commit: payload.required_commit(),
            durable_commit: request.progress_commit,
            state_root: payload.state_root(),
            lease_not_before_ms: payload.lease_not_before_ms(),
            lease_expires_at_ms: payload.lease_expires_at_ms(),
        };
        let expected_epoch = actor.highest_durable_epoch().saturating_add(1);
        if binding.epoch > expected_epoch {
            return Err(ProductionVoteError::EpochJump);
        }
        if let Some(code) = actor.preflight_vote(&binding) {
            return attest_vote_reply(
                ProductionVoteReply {
                    cluster_id: cluster_id.clone(),
                    witness_id: witness_id.clone(),
                    key_id: key_id.clone(),
                    binding,
                    code,
                    signed_vote: None,
                    durable_generation: None,
                    attestation: [0; 64],
                },
                signing_key,
            );
        }
        incarnations.record(&binding.candidate_node_id, binding.candidate_incarnation)?;
        let reply = actor.handle_vote(&binding);
        let signed_vote = if reply.is_granted() {
            Some(
                ProductionSignedVote::sign(
                    CanonicalId::new(cluster_id.clone())
                        .map_err(|_error| ProductionVoteError::Malformed)?,
                    &binding,
                    witness_id.clone(),
                    key_id.clone(),
                    signing_key,
                )
                .map_err(|_error| ProductionVoteError::Malformed)?,
            )
        } else {
            None
        };
        attest_vote_reply(
            ProductionVoteReply {
                cluster_id: cluster_id.clone(),
                witness_id: witness_id.clone(),
                key_id: key_id.clone(),
                binding,
                code: reply.code(),
                signed_vote,
                durable_generation: reply.durable_generation(),
                attestation: [0; 64],
            },
            signing_key,
        )
    }

    #[must_use]
    pub const fn is_vote_mode(&self) -> bool {
        matches!(self.mode, RuntimeMode::Vote(_))
    }

    #[must_use]
    pub fn matches_membership(&self, membership: &WitnessMembership) -> bool {
        let RuntimeMode::Vote(state) = &self.mode else {
            return false;
        };
        let candidate_ids: BTreeSet<_> = state
            .credentials
            .iter()
            .map(|credential| credential.node_id.as_str())
            .collect();
        let expected = BTreeSet::from([membership.node_a_id(), membership.node_b_id()]);
        state.witness_id.as_str() == membership.witness_id()
            && candidate_ids == expected
            && state.credentials.len() == 2
            && state.actor.policy_matches_candidates(expected)
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        match &self.mode {
            RuntimeMode::Management(admission) => admission.highest_sequence(),
            RuntimeMode::Vote(state) => state.actor.durable_generation(),
        }
    }

    #[must_use]
    pub fn highest_epoch(&self) -> u64 {
        match &self.mode {
            RuntimeMode::Management(_) => 0,
            RuntimeMode::Vote(state) => state.actor.highest_durable_epoch(),
        }
    }

    #[must_use]
    pub const fn effects_open(&self) -> bool {
        false
    }
}

fn attest_vote_reply(
    mut reply: ProductionVoteReply,
    signing_key: &SigningKey,
) -> Result<ProductionVoteReply, ProductionVoteError> {
    let statement = reply.encode_statement()?;
    reply.attestation = signing_key
        .sign(&vote_reply_attestation_preimage(&statement))
        .to_bytes();
    Ok(reply)
}

fn pin_witness_signer_identity(
    directory: &Path,
    witness_id: &CanonicalId,
    key_id: &CanonicalId,
    verifying_key: &VerifyingKey,
) -> Result<(), ProductionWitnessOpenError> {
    let witness_len = u8::try_from(witness_id.as_str().len())
        .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
    let key_len = u8::try_from(key_id.as_str().len())
        .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
    let mut statement = Vec::new();
    statement.extend_from_slice(SIGNER_IDENTITY_MAGIC);
    statement.push(witness_len);
    statement.extend_from_slice(witness_id.as_str().as_bytes());
    statement.push(key_len);
    statement.extend_from_slice(key_id.as_str().as_bytes());
    statement.extend_from_slice(&verifying_key.to_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"quorumarc/witness-signer-identity/v1\0");
    hasher.update(&statement);
    statement.extend_from_slice(&hasher.finalize());
    let path = directory.join("witness-signer.identity");
    match OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(&statement)
                .and_then(|()| file.sync_all())
                .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
            File::open(directory)
                .and_then(|parent| parent.sync_all())
                .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(OFlags::NOFOLLOW.bits() as i32)
                .open(&path)
                .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
            let metadata = file
                .metadata()
                .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
            if !metadata.is_file()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.len() != statement.len() as u64
            {
                return Err(ProductionWitnessOpenError::SignerIdentityMismatch);
            }
            let mut recovered = Vec::new();
            (&mut file)
                .take(1_024)
                .read_to_end(&mut recovered)
                .map_err(|_error| ProductionWitnessOpenError::SignerIdentityMismatch)?;
            if recovered != statement {
                return Err(ProductionWitnessOpenError::SignerIdentityMismatch);
            }
            Ok(())
        }
        Err(_error) => match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(ProductionWitnessOpenError::SignerIdentityMismatch)
            }
            Ok(_) | Err(_) => Err(ProductionWitnessOpenError::SignerIdentityMismatch),
        },
    }
}

fn acquire_witness_owner_lock(
    directory: &Path,
) -> Result<WitnessOwnerLock, ProductionWitnessOpenError> {
    let path = directory.join(".production-witness.owner");
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_error| ProductionWitnessOpenError::OwnerLockRefused)?;
    let metadata = file
        .metadata()
        .map_err(|_error| ProductionWitnessOpenError::OwnerLockRefused)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProductionWitnessOpenError::OwnerLockRefused);
    }
    flock(&file, FlockOperation::NonBlockingLockExclusive)
        .map_err(|_error| ProductionWitnessOpenError::OwnerLockRefused)?;
    Ok(WitnessOwnerLock { _file: file })
}

fn map_vote_frame_error(error: ProductionFrameError) -> ProductionVoteError {
    match error {
        ProductionFrameError::Malformed => ProductionVoteError::Malformed,
        ProductionFrameError::AuthenticationFailed => ProductionVoteError::AuthenticationFailed,
    }
}

/// Errors during Witness server operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessServerError {
    SocketBindFailed,
    SocketServeFailed,
    StateUnavailable,
    InvalidRuntime,
}

/// Production Witness TCP server with rustls mTLS authentication.
#[derive(Debug)]
pub struct ProductionWitnessServer {
    listener: TcpListener,
    tls_config: Arc<ServerConfig>,
    runtime: Arc<Mutex<ProductionWitnessRuntime>>,
}

impl ProductionWitnessServer {
    pub fn bind(
        membership: WitnessMembership,
        tls_config: MtlsServerConfig,
        runtime: ProductionWitnessRuntime,
    ) -> Result<Self, WitnessServerError> {
        if !runtime.matches_membership(&membership) {
            return Err(WitnessServerError::InvalidRuntime);
        }
        let listener = TcpListener::bind(membership.witness_address())
            .map_err(|_error| WitnessServerError::SocketBindFailed)?;
        Ok(Self {
            listener,
            tls_config: tls_config.into_arc(),
            runtime: Arc::new(Mutex::new(runtime)),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, WitnessServerError> {
        self.listener
            .local_addr()
            .map_err(|_error| WitnessServerError::SocketBindFailed)
    }

    pub fn serve_until(self, shutdown: &ShutdownToken) -> Result<(), WitnessServerError> {
        self.listener
            .set_nonblocking(true)
            .map_err(|_error| WitnessServerError::SocketServeFailed)?;
        let mut workers = Vec::new();
        while !shutdown.is_requested() {
            reap_finished_workers(&mut workers);
            match self.listener.accept() {
                Ok((stream, _addr)) if workers.len() < MAX_WITNESS_CONNECTIONS => {
                    let control = stream
                        .try_clone()
                        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
                    let tls_config = Arc::clone(&self.tls_config);
                    let runtime = Arc::clone(&self.runtime);
                    let handle = thread::Builder::new()
                        .name("quorumarc-witness-conn".to_owned())
                        .spawn(move || {
                            let _ = serve_stream(stream, tls_config, runtime);
                        })
                        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
                    workers.push(ConnectionWorker { control, handle });
                }
                Ok((stream, _addr)) => {
                    let _ = stream.shutdown(Shutdown::Both);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    shutdown.wait_timeout(Duration::from_millis(20));
                }
                Err(_error) => return Err(WitnessServerError::SocketServeFailed),
            }
        }
        for worker in &workers {
            let _ = worker.control.shutdown(Shutdown::Both);
        }
        for worker in workers {
            let _ = worker.handle.join();
        }
        Ok(())
    }
}

struct ConnectionWorker {
    control: TcpStream,
    handle: JoinHandle<()>,
}

fn reap_finished_workers(workers: &mut Vec<ConnectionWorker>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].handle.is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.handle.join();
        } else {
            index += 1;
        }
    }
}

fn serve_stream(
    stream: TcpStream,
    tls_config: Arc<ServerConfig>,
    runtime: Arc<Mutex<ProductionWitnessRuntime>>,
) -> Result<(), WitnessServerError> {
    stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(WITNESS_IO_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(WITNESS_IO_TIMEOUT)))
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let connection = ServerConnection::new(tls_config)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut length = [0_u8; 4];
    tls.read_exact(&mut length)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let frame_len = u32::from_be_bytes(length) as usize;
    if frame_len == 0 || frame_len > MAX_WITNESS_FRAME {
        return write_witness_response(&mut tls, b"MALFORMED\n");
    }
    let mut frame = vec![0_u8; frame_len];
    tls.read_exact(&mut frame)
        .map_err(|_error| WitnessServerError::SocketServeFailed)?;
    let response = {
        let mut runtime = runtime
            .lock()
            .map_err(|_error| WitnessServerError::StateUnavailable)?;
        match runtime.handle_vote(&frame) {
            Ok(reply) => reply
                .encode()
                .map_err(|_error| WitnessServerError::SocketServeFailed)?,
            Err(ProductionVoteError::Malformed) => b"MALFORMED\n".to_vec(),
            Err(ProductionVoteError::AuthenticationFailed) => b"AUTHENTICATION_FAILED\n".to_vec(),
            Err(ProductionVoteError::EpochJump) => b"EPOCH_JUMP_REFUSED\n".to_vec(),
            Err(ProductionVoteError::IncarnationRollback) => {
                b"INCARNATION_ROLLBACK_REFUSED\n".to_vec()
            }
            Err(ProductionVoteError::IncarnationIo) => b"DURABILITY_REFUSED\n".to_vec(),
            Err(ProductionVoteError::UnsupportedRuntime) => {
                return Err(WitnessServerError::InvalidRuntime);
            }
        }
    };
    write_witness_response(&mut tls, &response)
}

fn write_witness_response(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    response: &[u8],
) -> Result<(), WitnessServerError> {
    let length =
        u32::try_from(response.len()).map_err(|_error| WitnessServerError::SocketServeFailed)?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|()| stream.write_all(response))
        .and_then(|()| stream.flush())
        .map_err(|_error| WitnessServerError::SocketServeFailed)
}
