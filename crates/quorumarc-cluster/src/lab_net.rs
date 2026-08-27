use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::{ClusterError, err};

const PRIVATE_LAN_NETWORK: Ipv4Addr = Ipv4Addr::new(172, 30, 1, 0);
const PRIVATE_LAN_PREFIX: u8 = 24;
const PRIVATE_LAN_BROADCAST: Ipv4Addr = Ipv4Addr::new(172, 30, 1, 255);

/// Bind and connect policy for bounded laboratory transports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabBindPolicy {
    /// Existing Gate 1A localhost-only laboratory.
    LoopbackOnly,
    /// Explicit two-host private-LAN laboratory on 172.30.1.0/24.
    PrivateLan,
}

impl LabBindPolicy {
    /// Selects the laboratory bind policy from mutually documented opt-in flags.
    pub fn from_flags(
        allow_lifecycle_lab: bool,
        allow_private_lan_lab: bool,
    ) -> Result<Self, ClusterError> {
        match (allow_lifecycle_lab, allow_private_lan_lab) {
            (_, false) => Ok(Self::LoopbackOnly),
            (true, true) => Ok(Self::PrivateLan),
            (false, true) => Err(err(
                "PRIVATE_LAN_LAB_REFUSED",
                "private-LAN mode also requires the matching laboratory opt-in",
            )),
        }
    }

    /// Returns whether this policy is the explicit private-LAN laboratory.
    #[must_use]
    pub const fn allows_private_lan(self) -> bool {
        matches!(self, Self::PrivateLan)
    }
}

/// Refuses addresses that the selected laboratory policy does not permit.
pub fn ensure_lab_bind(policy: LabBindPolicy, address: SocketAddr) -> Result<(), ClusterError> {
    if address.ip().is_loopback() {
        return Ok(());
    }
    match policy {
        LabBindPolicy::LoopbackOnly => Err(err(
            "NON_LOOPBACK_REFUSED",
            format!("{address} is outside the bounded localhost lifecycle lab"),
        )),
        LabBindPolicy::PrivateLan if private_lan_host(address.ip()) => Ok(()),
        LabBindPolicy::PrivateLan => Err(err(
            "PRIVATE_LAN_ADDRESS_REFUSED",
            format!("{address} is outside the bounded 172.30.1.0/24 laboratory"),
        )),
    }
}

/// Refuses a connection unless its source is allowed and exactly pinned.
pub fn ensure_lab_peer(
    policy: LabBindPolicy,
    remote: SocketAddr,
    expected_ips: &[IpAddr],
) -> Result<(), ClusterError> {
    ensure_lab_bind(policy, remote)?;
    if policy == LabBindPolicy::LoopbackOnly && remote.ip().is_loopback() {
        return Ok(());
    }
    if expected_ips.contains(&remote.ip()) {
        Ok(())
    } else {
        Err(err(
            "PRIVATE_LAN_PEER_REFUSED",
            format!("{} is not an expected laboratory source", remote.ip()),
        ))
    }
}

/// Validates peer source pinning and decrements the remaining connection budget
/// only on successful admission.
pub(crate) fn account_lab_peer(
    remaining: &mut u64,
    policy: LabBindPolicy,
    remote: SocketAddr,
    expected_ips: &[IpAddr],
) -> Result<(), ClusterError> {
    if *remaining == 0 {
        return Err(err(
            "LAB_CONNECTION_BUDGET_EXHAUSTED",
            "laboratory connection budget exhausted",
        ));
    }
    ensure_lab_peer(policy, remote, expected_ips)?;
    *remaining = remaining.saturating_sub(1);
    Ok(())
}

fn private_lan_host(ip: IpAddr) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    v4 != PRIVATE_LAN_NETWORK && v4 != PRIVATE_LAN_BROADCAST && in_private_lan(v4)
}

fn in_private_lan(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let network = PRIVATE_LAN_NETWORK.octets();
    let shift = 32_u32.saturating_sub(u32::from(PRIVATE_LAN_PREFIX));
    let mask = !((1_u32 << shift) - 1);
    u32::from_be_bytes(octets) & mask == u32::from_be_bytes(network) & mask
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn addr(octets: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((octets, port))
    }

    #[test]
    fn loopback_policy_rejects_private_lan_and_unspecified() {
        let policy = LabBindPolicy::from_flags(true, false).expect("loopback lab");
        assert_eq!(policy, LabBindPolicy::LoopbackOnly);
        ensure_lab_bind(policy, addr([127, 0, 0, 1], 9)).expect("loopback");
        assert_eq!(
            ensure_lab_bind(policy, addr([172, 30, 1, 22], 9))
                .expect_err("lan refused")
                .reason_code(),
            "NON_LOOPBACK_REFUSED"
        );
        assert_eq!(
            ensure_lab_bind(policy, addr([0, 0, 0, 0], 9))
                .expect_err("unspecified refused")
                .reason_code(),
            "NON_LOOPBACK_REFUSED"
        );
        assert_eq!(
            ensure_lab_bind(policy, addr([8, 8, 8, 8], 9))
                .expect_err("public refused")
                .reason_code(),
            "NON_LOOPBACK_REFUSED"
        );
    }

    #[test]
    fn private_lan_policy_requires_lifecycle_opt_in_and_accepts_only_172_30_1_hosts() {
        assert_eq!(
            LabBindPolicy::from_flags(false, true)
                .expect_err("private lan without lifecycle")
                .reason_code(),
            "PRIVATE_LAN_LAB_REFUSED"
        );
        let policy = LabBindPolicy::from_flags(true, true).expect("private lan lab");
        assert_eq!(policy, LabBindPolicy::PrivateLan);
        ensure_lab_bind(policy, addr([127, 0, 0, 1], 9)).expect("loopback still allowed");
        ensure_lab_bind(policy, addr([172, 30, 1, 21], 9)).expect("node b");
        ensure_lab_bind(policy, addr([172, 30, 1, 22], 7000)).expect("node a");
        for refused in [
            [172, 30, 1, 0],
            [172, 30, 1, 255],
            [172, 30, 0, 21],
            [10, 0, 0, 1],
            [192, 168, 1, 1],
            [8, 8, 8, 8],
            [0, 0, 0, 0],
        ] {
            assert_eq!(
                ensure_lab_bind(policy, addr(refused, 9))
                    .expect_err("out of subnet")
                    .reason_code(),
                "PRIVATE_LAN_ADDRESS_REFUSED"
            );
        }
    }

    #[test]
    fn private_lan_peer_requires_an_exact_expected_source_ip() {
        let policy = LabBindPolicy::from_flags(true, true).expect("private lan lab");
        let expected = [IpAddr::V4(Ipv4Addr::new(172, 30, 1, 22))];
        ensure_lab_peer(policy, addr([172, 30, 1, 22], 40_001), &expected)
            .expect("expected source");
        assert_eq!(
            ensure_lab_peer(policy, addr([172, 30, 1, 21], 40_002), &expected)
                .expect_err("unexpected source")
                .reason_code(),
            "PRIVATE_LAN_PEER_REFUSED"
        );
        assert_eq!(
            ensure_lab_peer(policy, addr([8, 8, 8, 8], 40_003), &expected)
                .expect_err("public source")
                .reason_code(),
            "PRIVATE_LAN_ADDRESS_REFUSED"
        );
        assert_eq!(
            ensure_lab_peer(policy, addr([127, 0, 0, 1], 9), &expected)
                .expect_err("unpinned loopback")
                .reason_code(),
            "PRIVATE_LAN_PEER_REFUSED"
        );
        let loopback_expected = [IpAddr::V4(Ipv4Addr::LOCALHOST)];
        ensure_lab_peer(policy, addr([127, 0, 0, 1], 9), &loopback_expected)
            .expect("pinned loopback");
    }

    #[test]
    fn refused_peers_do_not_consume_connection_budget() {
        let policy = LabBindPolicy::from_flags(true, true).expect("private lan lab");
        let expected = [IpAddr::V4(Ipv4Addr::new(172, 30, 1, 22))];
        let mut remaining = 1_u64;
        assert_eq!(
            account_lab_peer(&mut remaining, policy, addr([127, 0, 0, 1], 9), &expected)
                .expect_err("unpinned loopback")
                .reason_code(),
            "PRIVATE_LAN_PEER_REFUSED"
        );
        assert_eq!(remaining, 1);
        account_lab_peer(
            &mut remaining,
            policy,
            addr([172, 30, 1, 22], 40_001),
            &expected,
        )
        .expect("pinned source");
        assert_eq!(remaining, 0);
        assert_eq!(
            account_lab_peer(
                &mut remaining,
                policy,
                addr([172, 30, 1, 22], 40_002),
                &expected,
            )
            .expect_err("exhausted")
            .reason_code(),
            "LAB_CONNECTION_BUDGET_EXHAUSTED"
        );
        assert_eq!(remaining, 0);
    }

    #[test]
    fn private_lan_policy_rejects_non_loopback_ipv6() {
        let policy = LabBindPolicy::from_flags(true, true).expect("private lan lab");
        ensure_lab_bind(policy, SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, 9)))
            .expect("ipv6 loopback remains allowed");
        let address =
            SocketAddr::from((std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 9));
        assert_eq!(
            ensure_lab_bind(policy, address)
                .expect_err("ipv6 unicast refused")
                .reason_code(),
            "PRIVATE_LAN_ADDRESS_REFUSED"
        );
    }
}
