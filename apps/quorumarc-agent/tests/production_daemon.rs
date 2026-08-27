#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

const PRODUCTION_CONFIG: &str = r#"
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
fn production_daemon_stays_effect_closed_until_sigterm_drain() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-daemon-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, PRODUCTION_CONFIG)?;

    let socket = directory.join("status.sock");
    let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut child)?;
    for _ in 0..2 {
        let mut client = UnixStream::connect(&socket)?;
        client.write_all(b"PROMOTE\n")?;
        let mut body = String::new();
        client.read_to_string(&mut body)?;
        assert!(body.contains("\"effect_gate\":\"closed\""));
        assert!(body.contains("\"authority_enabled\":false"));
        assert!(!body.contains("PROMOTE"));
    }

    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()?;
    assert!(status.success());
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(output.status.success(), "stderr={stderr}");
    assert!(stdout.contains("DAEMON_STOPPED_EFFECT_CLOSED"));
    assert!(stdout.contains("\"effect_gate\":\"closed\""));
    assert!(stdout.contains("\"authority\":\"denied\""));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

fn wait_for_socket(path: &std::path::Path, child: &mut Child) -> Result<(), Box<dyn Error>> {
    for _ in 0..50 {
        if child.try_wait()?.is_some() {
            return Err("daemon exited before status socket".into());
        }
        if path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("status socket was not created".into())
}
