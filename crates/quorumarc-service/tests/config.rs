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
