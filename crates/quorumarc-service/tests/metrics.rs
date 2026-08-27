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
address = "172.30.1.200:7602"
failure_domain = "power-w"
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
