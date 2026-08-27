use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
        if same_host(node_a.ip(), witness.ip()) || same_host(node_b.ip(), witness.ip()) {
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

use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::management_journal::{JournalError, ManagementJournal, ManagementOutcome};
use crate::protocol::{AdmissionError, AuthenticatedRequestJournal};

/// Independent Witness that records authenticated votes without opening effects.
#[derive(Debug)]
pub struct ProductionWitnessRuntime {
    admission: AuthenticatedRequestJournal,
}

impl ProductionWitnessRuntime {
    pub fn open(
        directory: &Path,
        identity: [u8; 16],
        node_id: impl Into<String>,
        key_id: impl Into<String>,
        verifying_key: VerifyingKey,
    ) -> Result<Self, JournalError> {
        let journal = ManagementJournal::open(directory, identity)?;
        Ok(Self {
            admission: AuthenticatedRequestJournal::new(journal, node_id, key_id, verifying_key),
        })
    }

    pub fn admit_vote(&mut self, bytes: &[u8]) -> Result<ManagementOutcome, AdmissionError> {
        self.admission.admit(bytes)
    }

    #[must_use]
    pub fn highest_sequence(&self) -> u64 {
        self.admission.highest_sequence()
    }

    #[must_use]
    pub const fn effects_open(&self) -> bool {
        false
    }
}
