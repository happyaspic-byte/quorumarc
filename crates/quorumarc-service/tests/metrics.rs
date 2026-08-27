#![allow(clippy::expect_used)]

use quorumarc_service::config::ProductionConfig;
use quorumarc_service::metrics::prometheus_text;

const SAMPLE_CONFIG: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "node-a"
workload_id = "orders-api"
role = "data"
listen = "172.30.1.22:7601"
witness = "172.30.1.200:7602"
store_dir = "/var/lib/quorumarc/authority"
signing_key = "/etc/quorumarc/secrets/node-a.seed"
key_id = "node-a-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = true

[tls]
certificate_chain = "/etc/quorumarc/tls/node-a.crt"
private_key = "/etc/quorumarc/tls/node-a.key"
trusted_roots = "/etc/quorumarc/tls/ca.crt"
server_name = "witness.example.internal"
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
address = "172.30.1.200:7602"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "/etc/quorumarc/keys/witness-a.pub"
"#;

#[test]
fn prometheus_metrics_are_low_cardinality_and_omit_secrets() {
    let config = ProductionConfig::parse(SAMPLE_CONFIG).expect("valid config");
    let text = prometheus_text(&config, "closed", 0, 123_456, Some(42));
    assert!(text.contains("quorumarc_effect_gate_open 0"));
    assert!(text.contains("quorumarc_authority_enabled 0"));
    assert!(text.contains("quorumarc_members 3"));
    assert!(text.contains("quorumarc_uptime_ms 123456"));
    assert!(text.contains("quorumarc_last_committed_index 42"));
    assert!(!text.contains("node-a"));
    assert!(!text.contains("prod-cluster"));
    assert!(!text.contains("/etc/quorumarc/secrets"));
    assert!(!text.contains("172.30.1.84"));
}
