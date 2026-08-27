#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_service::config::{ConfigError, ProductionConfig};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const VALID: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.23:7602"
store_dir = "/var/lib/quorumarc/authority"
store_id = "07070707070707070707070707070707"
signing_key = "/etc/quorumarc/node-a.seed"
key_id = "node-a-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = true

[tls]
certificate_chain = "/etc/quorumarc/tls/node-a.crt"
private_key = "/etc/quorumarc/tls/node-a.key"
trusted_roots = "/etc/quorumarc/tls/ca.crt"
server_name = "witness.example.internal"
io_timeout_ms = 5000

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
key_id = "node-a-2026-01"
public_key = "/etc/quorumarc/keys/node-a.pub"

[[members]]
id = "node-b"
role = "data"
address = "172.30.1.21:7601"
failure_domain = "power-b"
key_id = "node-b-2026-01"
public_key = "/etc/quorumarc/keys/node-b.pub"

[[members]]
id = "witness-a"
role = "witness"
address = "172.30.1.23:7602"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "/etc/quorumarc/keys/witness-a.pub"
"#;

#[test]
fn production_config_accepts_exact_three_member_hardware_fenced_profile() {
    let config = ProductionConfig::parse(VALID).expect("valid production config");
    assert_eq!(config.cluster_id(), "prod-cluster");
    assert_eq!(config.members().len(), 3);
    assert!(config.automatic_promotion());
    assert_eq!(config.key_id(), "node-a-2026-01");
    assert_eq!(config.policy_hash(), [23; 32]);
    assert_eq!(config.max_lease_duration_ms(), 5_000);
    assert_eq!(config.store_id(), [7; 16]);
    assert_eq!(config.tls_io_timeout_ms(), 5_000);
    let node_b = config
        .members()
        .iter()
        .find(|member| member.id == "node-b")
        .expect("node b");
    assert_eq!(node_b.key_id, "node-b-2026-01");
    assert_eq!(
        node_b.public_key,
        std::path::Path::new("/etc/quorumarc/keys/node-b.pub")
    );
    assert_eq!(config.effect_gate_state(), "closed");
}

#[test]
fn production_config_requires_absolute_mtls_paths_and_server_name() {
    let config = ProductionConfig::parse(VALID).expect("valid production config");
    assert_eq!(
        config.tls_certificate_chain(),
        std::path::Path::new("/etc/quorumarc/tls/node-a.crt")
    );
    assert_eq!(
        config.tls_private_key(),
        std::path::Path::new("/etc/quorumarc/tls/node-a.key")
    );
    assert_eq!(
        config.tls_trusted_roots(),
        std::path::Path::new("/etc/quorumarc/tls/ca.crt")
    );
    assert_eq!(config.tls_server_name(), "witness.example.internal");

    for relative in [
        "etc/quorumarc/tls/node-a.crt",
        "etc/quorumarc/tls/node-a.key",
        "etc/quorumarc/tls/ca.crt",
    ] {
        let invalid = VALID.replace(&format!("/{}", relative), relative);
        assert!(matches!(
            ProductionConfig::parse(&invalid),
            Err(ConfigError::PathMustBeAbsolute(_))
        ));
    }

    let invalid_server_name = VALID.replace(
        "server_name = \"witness.example.internal\"",
        "server_name = \"127.0.0.1\"",
    );
    assert!(matches!(
        ProductionConfig::parse(&invalid_server_name),
        Err(ConfigError::InvalidValue(_))
    ));
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

#[test]
fn production_prerequisites_refuse_missing_store_and_signing_key() {
    let config = ProductionConfig::parse(VALID).expect("valid production config");
    assert!(matches!(
        config.verify_local_prerequisites(),
        Err(ConfigError::StoreUnavailable)
    ));
}

#[test]
fn production_prerequisites_accept_restricted_store_and_key() {
    let (directory, config) = isolated_production_config();
    let store = directory.join("store");
    let key = directory.join("node.seed");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");
    fs::write(&key, [7_u8; 32]).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");
    let config = ProductionConfig::parse(&config).expect("parse");
    config
        .verify_local_prerequisites()
        .expect("restricted store and key");
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_prerequisites_refuse_group_readable_key_and_symlink_store() {
    let (directory, config_text) = isolated_production_config();
    let store = directory.join("store");
    let key = directory.join("node.seed");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");
    fs::write(&key, [7_u8; 32]).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o640)).expect("group readable");
    let config = ProductionConfig::parse(&config_text).expect("parse");
    assert!(matches!(
        config.verify_local_prerequisites(),
        Err(ConfigError::SigningKeyUnavailable)
    ));

    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("restore key");
    let alias = directory.join("alias-store");
    let _ = fs::remove_dir(&store);
    fs::create_dir(&alias).expect("alias");
    fs::set_permissions(&alias, fs::Permissions::from_mode(0o700)).expect("alias mode");
    symlink(&alias, &store).expect("symlink store");
    assert!(matches!(
        config.verify_local_prerequisites(),
        Err(ConfigError::StoreUnavailable)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_store_lock_refuses_second_holder_until_release() {
    let (directory, config_text) = isolated_production_config();
    let store = directory.join("store");
    let key = directory.join("node.seed");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");
    fs::write(&key, [7_u8; 32]).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");
    let config = ProductionConfig::parse(&config_text).expect("parse");
    let first = config.acquire_store_lock().expect("first lock");
    assert!(matches!(
        config.acquire_store_lock(),
        Err(ConfigError::OwnerLockRefused)
    ));
    drop(first);
    let lock_path = store.join(".quorumarc.owner");
    let metadata = fs::metadata(&lock_path).expect("lock metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let _second = config.acquire_store_lock().expect("released lock");

    fs::remove_file(&lock_path).expect("remove lock");
    let target = directory.join("elsewhere.owner");
    fs::write(&target, b"hijack").expect("target");
    symlink(&target, &lock_path).expect("symlink lock");
    assert!(matches!(
        config.acquire_store_lock(),
        Err(ConfigError::OwnerLockRefused)
    ));
    let _ = fs::remove_dir_all(directory);
}

#[test]
fn production_prerequisites_refuse_zero_seed_and_symlink_key() {
    let (directory, config_text) = isolated_production_config();
    let store = directory.join("store");
    let key = directory.join("node.seed");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");
    fs::write(&key, [0_u8; 32]).expect("zero key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("key mode");
    let config = ProductionConfig::parse(&config_text).expect("parse");
    assert!(matches!(
        config.verify_local_prerequisites(),
        Err(ConfigError::SigningKeyUnavailable)
    ));

    let material = directory.join("material.seed");
    fs::write(&material, [7_u8; 32]).expect("material");
    fs::set_permissions(&material, fs::Permissions::from_mode(0o600)).expect("material mode");
    fs::remove_file(&key).expect("remove zero key");
    symlink(&material, &key).expect("symlink key");
    assert!(matches!(
        config.verify_local_prerequisites(),
        Err(ConfigError::SigningKeyUnavailable)
    ));
    let _ = fs::remove_dir_all(directory);
}

fn isolated_production_config() -> (std::path::PathBuf, String) {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-prereq-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let store = directory.join("store");
    let key = directory.join("node.seed");
    let text = VALID
        .replace(
            "/var/lib/quorumarc/authority",
            store.to_str().expect("utf8"),
        )
        .replace("/etc/quorumarc/node-a.seed", key.to_str().expect("utf8"));
    (directory, text)
}
