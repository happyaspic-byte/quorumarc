#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
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
    fs::write(&config, witness_config_with_prerequisites(&directory)?)?;

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

#[test]
fn production_witness_daemon_handles_sighup_reload_and_stops_on_sigterm()
-> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-witness-reload-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("witness.toml");
    let config_text = witness_config_with_prerequisites(&directory)?;
    fs::write(&config, &config_text)?;
    let socket = directory.join("status.sock");

    let mut child = Command::new(env!("CARGO_BIN_EXE_quorumarc-witness"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut child)?;
    let initial = read_status(&socket)?;
    assert!(initial.contains("\"log_level\":\"info\""));
    assert!(initial.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(initial.contains("\"effect_gate\":\"closed\""));

    fs::write(
        &config,
        config_text.replace(
            "automatic_promotion = false",
            "automatic_promotion = false\nlog_level = \"debug\"",
        ),
    )?;
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    let reloaded = wait_for_status(&socket, "\"log_level\":\"debug\"")?;
    assert!(reloaded.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(reloaded.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    fs::write(
        &config,
        config_text
            .replace(
                "automatic_promotion = false",
                "automatic_promotion = false\nlog_level = \"debug\"",
            )
            .replace("cluster_id = \"prod-cluster\"", "cluster_id = \"other\""),
    )?;
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.id().to_string()])
            .status()?
            .success()
    );
    thread::sleep(Duration::from_millis(200));
    let refused = read_status(&socket)?;
    assert!(refused.contains("\"log_level\":\"debug\""));
    assert!(refused.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(refused.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()?
            .success()
    );
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(stdout.contains("WITNESS_DAEMON_STOPPED_NONVOTING"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

fn witness_config_with_prerequisites(
    directory: &std::path::Path,
) -> Result<String, Box<dyn Error>> {
    let store = directory.join("store");
    let key = directory.join("witness.seed");
    fs::create_dir(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
    fs::write(&key, [9_u8; 32])?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    Ok(WITNESS_CONFIG
        .replace(
            "/var/lib/quorumarc-witness/control",
            store.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/secrets/witness-a.seed",
            key.to_str().ok_or("utf8")?,
        ))
}

fn read_status(socket: &std::path::Path) -> Result<String, Box<dyn Error>> {
    let mut client = UnixStream::connect(socket)?;
    let mut body = String::new();
    client.read_to_string(&mut body)?;
    Ok(body)
}

fn wait_for_status(socket: &std::path::Path, needle: &str) -> Result<String, Box<dyn Error>> {
    for _ in 0..50 {
        if let Ok(body) = read_status(socket) {
            if body.contains(needle) {
                return Ok(body);
            }
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("status never matched".into())
}

fn wait_for_socket(
    path: &std::path::Path,
    child: &mut std::process::Child,
) -> Result<(), Box<dyn Error>> {
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
