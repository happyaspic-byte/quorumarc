use std::net::IpAddr;
use std::net::SocketAddr;

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
        if same_host(node_a.ip(), witness.ip()) || same_host(node_b.ip(), witness.ip()) {
            return Err(WitnessMembershipError::SharedHost);
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
    left == right
}
