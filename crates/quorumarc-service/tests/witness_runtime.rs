use std::net::SocketAddr;

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
}
