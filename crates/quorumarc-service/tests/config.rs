#![allow(clippy::expect_used)]

use quorumarc_service::config::{ConfigError, ProductionConfig};

const VALID: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.23:7602"
store_dir = "/var/lib/quorumarc/authority"
signing_key = "/etc/quorumarc/node-a.seed"
automatic_promotion = true

[fence]
mechanism = "hardware-power"
profile = "pdu-a"
read_back = true

[workload]
unit = "orders-api.service"

[effect]
vip = "172.30.1.100/24"
interface = "enp1s0"

[[members]]
id = "node-a"
role = "data"
address = "172.30.1.22:7601"
failure_domain = "power-a"

[[members]]
id = "node-b"
role = "data"
address = "172.30.1.21:7601"
failure_domain = "power-b"

[[members]]
id = "witness-a"
role = "witness"
address = "172.30.1.23:7602"
failure_domain = "power-w"
"#;

#[test]
fn production_config_accepts_exact_three_member_hardware_fenced_profile() {
    let config = ProductionConfig::parse(VALID).expect("valid production config");
    assert_eq!(config.cluster_id(), "prod-cluster");
    assert_eq!(config.members().len(), 3);
    assert!(config.automatic_promotion());
    assert_eq!(config.effect_gate_state(), "closed");
}

#[test]
fn automatic_promotion_rejects_gate_expiry_and_shared_witness_profiles() {
    let gate_expiry = VALID.replace("hardware-power", "effect-gate-expired");
    assert!(matches!(
        ProductionConfig::parse(&gate_expiry),
        Err(ConfigError::AutomaticPromotionRequiresAuthoritativeFence)
    ));

    let shared_witness = VALID.replace("172.30.1.23:7602", "172.30.1.22:7602");
    assert!(matches!(
        ProductionConfig::parse(&shared_witness),
        Err(ConfigError::WitnessFailureDomainNotIndependent)
    ));
}

#[test]
fn automatic_promotion_requires_read_back_and_three_distinct_failure_domains() {
    let no_read_back = VALID.replace("read_back = true", "read_back = false");
    assert!(matches!(
        ProductionConfig::parse(&no_read_back),
        Err(ConfigError::FenceReadBackRequired)
    ));

    let shared_domain = VALID.replace(
        "failure_domain = \"power-w\"",
        "failure_domain = \"power-a\"",
    );
    assert!(matches!(
        ProductionConfig::parse(&shared_domain),
        Err(ConfigError::FailureDomainNotIndependent)
    ));
}

#[test]
fn production_witness_refuses_reserved_controller_host() {
    let controller_witness = VALID.replace("172.30.1.23:7602", "172.30.1.84:7602");
    assert!(matches!(
        ProductionConfig::parse(&controller_witness),
        Err(ConfigError::ReservedWitnessHost)
    ));

    let mapped = VALID.replace("172.30.1.23:7602", "[::ffff:172.30.1.84]:7602");
    assert!(matches!(
        ProductionConfig::parse(&mapped),
        Err(ConfigError::ReservedWitnessHost)
    ));
}

#[test]
fn production_config_requires_exact_roles_and_bound_local_identity() {
    let all_data = VALID.replace("role = \"witness\"", "role = \"data\"");
    assert!(matches!(
        ProductionConfig::parse(&all_data),
        Err(ConfigError::InvalidTopology)
    ));

    let unknown_role = VALID.replacen("role = \"data\"", "role = \"candidate\"", 1);
    assert!(matches!(
        ProductionConfig::parse(&unknown_role),
        Err(ConfigError::InvalidTopology)
    ));

    let missing_local = VALID.replace("node_id = \"node-a\"", "node_id = \"node-c\"");
    assert!(matches!(
        ProductionConfig::parse(&missing_local),
        Err(ConfigError::LocalIdentityMismatch)
    ));

    let wrong_listen = VALID.replacen(
        "listen = \"172.30.1.22:7601\"",
        "listen = \"172.30.1.22:7999\"",
        1,
    );
    assert!(matches!(
        ProductionConfig::parse(&wrong_listen),
        Err(ConfigError::LocalIdentityMismatch)
    ));
}

#[test]
fn production_config_requires_unique_member_ids_addresses_and_data_hosts() {
    let duplicate_id = VALID.replace("id = \"node-b\"", "id = \"node-a\"");
    assert!(matches!(
        ProductionConfig::parse(&duplicate_id),
        Err(ConfigError::InvalidTopology)
    ));

    let duplicate_address = VALID.replace("172.30.1.21:7601", "172.30.1.22:7601");
    assert!(matches!(
        ProductionConfig::parse(&duplicate_address),
        Err(ConfigError::InvalidTopology)
    ));

    let shared_data_host = VALID.replace("172.30.1.21:7601", "172.30.1.22:7609");
    assert!(matches!(
        ProductionConfig::parse(&shared_data_host),
        Err(ConfigError::InvalidTopology)
    ));
}

#[test]
fn production_config_requires_witness_endpoint_to_match_witness_member() {
    let unbound = VALID.replacen(
        "witness = \"172.30.1.23:7602\"",
        "witness = \"172.30.1.99:7602\"",
        1,
    );
    assert!(matches!(
        ProductionConfig::parse(&unbound),
        Err(ConfigError::WitnessEndpointMismatch)
    ));
}

#[test]
fn unknown_duplicate_and_relative_paths_fail_closed() {
    assert!(matches!(
        ProductionConfig::parse(&format!("{VALID}surprise = \"unsafe\"\n")),
        Err(ConfigError::UnknownField(_))
    ));
    let duplicate = VALID.replacen(
        "cluster_id = \"prod-cluster\"",
        "cluster_id = \"prod-cluster\"\ncluster_id = \"other\"",
        1,
    );
    assert!(matches!(
        ProductionConfig::parse(&duplicate),
        Err(ConfigError::DuplicateField(_))
    ));
    let relative = VALID.replace(
        "/var/lib/quorumarc/authority",
        "var/lib/quorumarc/authority",
    );
    assert!(matches!(
        ProductionConfig::parse(&relative),
        Err(ConfigError::PathMustBeAbsolute(_))
    ));
}

#[test]
fn production_reload_swaps_log_level_and_refuses_safety_changes() {
    let current = ProductionConfig::parse(VALID).expect("valid production config");
    assert_eq!(current.log_level(), "info");

    let debug = VALID.replace(
        "automatic_promotion = true",
        "automatic_promotion = true\nlog_level = \"debug\"",
    );
    let reloaded = current.reload(&debug).expect("safe log-level reload");
    assert_eq!(reloaded.log_level(), "debug");
    assert_eq!(reloaded.cluster_id(), current.cluster_id());
    assert_eq!(reloaded.node_id(), current.node_id());
    assert_eq!(reloaded.effect_gate_state(), "closed");

    let cluster = VALID.replace("cluster_id = \"prod-cluster\"", "cluster_id = \"other\"");
    assert!(matches!(
        current.reload(&cluster),
        Err(ConfigError::UnsafeReload)
    ));

    let fence = VALID.replace("hardware-power", "storage-reservation");
    assert!(matches!(
        current.reload(&fence),
        Err(ConfigError::UnsafeReload)
    ));
}
