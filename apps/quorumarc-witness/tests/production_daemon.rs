#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const WITNESS_CONFIG: &str = r#"
schema_version = "1"
cluster_id = "prod-cluster"
node_id = "witness-a"
workload_id = "orders-api"
role = "witness"
listen = "172.30.1.200:7602"
witness = "172.30.1.200:7602"
store_dir = "/var/lib/quorumarc-witness/control"
signing_key = "/etc/quorumarc/secrets/witness-a.seed"
automatic_promotion = false
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
fn production_witness_daemon_stays_nonvoting_until_sigterm_drain() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-daemon-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("witness.toml");
    fs::write(&config, WITNESS_CONFIG)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    thread::sleep(Duration::from_millis(100));
    assert!(child.try_wait()?.is_none(), "witness exited before SIGTERM");

    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "stderr={stderr}");
    assert!(stdout.contains("WITNESS_DAEMON_STOPPED_NONVOTING"));
    assert!(stdout.contains("voting=false"));
    assert!(stdout.contains("effect_gate=closed"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}
