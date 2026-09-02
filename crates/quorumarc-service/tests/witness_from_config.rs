#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use ed25519_dalek::SigningKey;
use quorumarc_service::config::ProductionConfig;
use quorumarc_service::witness::ProductionWitnessServer;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

#[test]
fn production_witness_server_builds_from_validated_config_and_material() {
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-from-config-{}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("directory");
    let store = directory.join("store");
    fs::create_dir(&store).expect("store");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).expect("store mode");

    let witness = SigningKey::from_bytes(&[29; 32]);
    let node_a = SigningKey::from_bytes(&[7; 32]);
    let node_b = SigningKey::from_bytes(&[9; 32]);
    let witness_seed = directory.join("witness.seed");
    let witness_public = directory.join("witness.pub");
    let node_a_public = directory.join("node-a.pub");
    let node_b_public = directory.join("node-b.pub");
    write_private(&witness_seed, &witness.to_bytes());
    fs::write(&witness_public, witness.verifying_key().to_bytes()).expect("witness public");
    fs::write(&node_a_public, node_a.verifying_key().to_bytes()).expect("node a public");
    fs::write(&node_b_public, node_b.verifying_key().to_bytes()).expect("node b public");

    let (certificate, tls_key, root) = issue_server_material();
    let certificate_path = directory.join("witness.crt");
    let tls_key_path = directory.join("witness.key");
    let root_path = directory.join("ca.crt");
    fs::write(&certificate_path, certificate).expect("certificate");
    write_private(&tls_key_path, tls_key.as_bytes());
    fs::write(&root_path, root).expect("root");

    let text = format!(
        r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "witness-a"
workload_id = "orders-api"
role = "witness"
listen = "127.0.0.1:0"
witness = "127.0.0.1:0"
store_dir = "{}"
store_id = "09090909090909090909090909090909"
signing_key = "{}"
key_id = "witness-2026-01"
policy_hash = "1717171717171717171717171717171717171717171717171717171717171717"
max_lease_duration_ms = 5000
automatic_promotion = false
[tls]
certificate_chain = "{}"
private_key = "{}"
trusted_roots = "{}"
server_name = "witness.test"
io_timeout_ms = 1000
[fence]
mechanism = "hardware-power"
profile = "pdu-a"
read_back = true
[workload]
unit = "orders-api.service"
[effect]
vip = "127.0.0.100/24"
interface = "lo"
[[members]]
id = "node-a"
role = "data"
address = "127.0.0.2:7601"
failure_domain = "power-a"
key_id = "node-a-2026-01"
public_key = "{}"
[[members]]
id = "node-b"
role = "data"
address = "127.0.0.3:7601"
failure_domain = "power-b"
key_id = "node-b-2026-01"
public_key = "{}"
[[members]]
id = "witness-a"
role = "witness"
address = "127.0.0.1:0"
failure_domain = "power-w"
key_id = "witness-2026-01"
public_key = "{}"
"#,
        store.display(),
        witness_seed.display(),
        certificate_path.display(),
        tls_key_path.display(),
        root_path.display(),
        node_a_public.display(),
        node_b_public.display(),
        witness_public.display(),
    );
    let config = ProductionConfig::parse(&text).expect("config");
    let server = ProductionWitnessServer::from_config(&config).expect("server");
    assert_ne!(server.local_addr().expect("local address").port(), 0);
    drop(server);

    fs::write(&witness_public, node_a.verifying_key().to_bytes()).expect("wrong witness public");
    assert!(matches!(
        ProductionWitnessServer::from_config(&config),
        Err(quorumarc_service::witness::ProductionWitnessOpenError::KeyMaterial)
    ));

    fs::write(&witness_public, witness.verifying_key().to_bytes()).expect("restore witness public");
    fs::set_permissions(&store, fs::Permissions::from_mode(0o755)).expect("unsafe store mode");
    assert!(matches!(
        ProductionWitnessServer::from_config(&config),
        Err(quorumarc_service::witness::ProductionWitnessOpenError::InvalidConfiguration)
    ));
    let _ = fs::remove_dir_all(directory);
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private write");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
}

fn issue_server_material() -> (String, String, String) {
    let mut ca_params = CertificateParams::new(vec!["quorumarc-ca".to_owned()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    let ca_key = KeyPair::generate().expect("ca key");
    let ca = ca_params.self_signed(&ca_key).expect("ca");
    let mut server_params =
        CertificateParams::new(vec!["witness.test".to_owned()]).expect("server params");
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().expect("server key");
    let server = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server certificate");
    (server.pem(), server_key.serialize_pem(), ca.pem())
}
