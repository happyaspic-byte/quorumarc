use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use quorumarc_service::witness::{WitnessMembership, WitnessMembershipError};

#[test]
fn witness_membership_requires_two_data_nodes_and_independent_witness() {
    let membership = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 23], 7602)),
        "power-w",
    );
    assert!(membership.is_ok());

    assert!(matches!(
        WitnessMembership::new(
            "node-a",
            SocketAddr::from(([172, 30, 1, 22], 7601)),
            "power-a",
            "node-b",
            SocketAddr::from(([172, 30, 1, 21], 7601)),
            "power-b",
            "witness-a",
            SocketAddr::from(([172, 30, 1, 22], 7602)),
            "power-w",
        ),
        Err(WitnessMembershipError::SharedHost)
    ));

    let mapped_shared = WitnessMembership::new(
        "node-a",
        SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(172, 30, 1, 22).to_ipv6_mapped()),
            7601,
        ),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 22], 7602)),
        "power-w",
    );
    assert!(matches!(
        mapped_shared,
        Err(WitnessMembershipError::SharedHost)
    ));
}

#[test]
fn witness_membership_refuses_reserved_host_and_duplicate_nodes() {
    let reserved = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 84], 7602)),
        "power-w",
    );
    assert!(matches!(
        reserved,
        Err(WitnessMembershipError::ReservedWitnessHost)
    ));

    let mapped_reserved = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-b",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::new(
            IpAddr::V6(Ipv4Addr::new(172, 30, 1, 84).to_ipv6_mapped()),
            7602,
        ),
        "power-w",
    );
    assert!(matches!(
        mapped_reserved,
        Err(WitnessMembershipError::ReservedWitnessHost)
    ));

    let same_candidate = WitnessMembership::new(
        "node-a",
        SocketAddr::from(([172, 30, 1, 22], 7601)),
        "power-a",
        "node-a",
        SocketAddr::from(([172, 30, 1, 21], 7601)),
        "power-b",
        "witness-a",
        SocketAddr::from(([172, 30, 1, 23], 7602)),
        "power-w",
    );
    assert!(matches!(
        same_candidate,
        Err(WitnessMembershipError::DuplicateMember)
    ));
}
