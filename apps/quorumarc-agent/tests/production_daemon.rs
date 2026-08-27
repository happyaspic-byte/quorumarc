#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
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
fn production_daemon_refuses_missing_store_and_signing_key() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-prereq-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, PRODUCTION_CONFIG)?;

    let output = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(stderr.contains("CONFIG_STORE_UNAVAILABLE"));
    assert!(stderr.contains("\"effect_gate\":\"closed\""));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_stays_effect_closed_until_sigterm_drain() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-daemon-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    let config_text = production_config_with_prerequisites(&directory)?;
    fs::write(&config, &config_text)?;

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

#[test]
fn production_daemon_reloads_log_level_and_refuses_unsafe_sighup() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-reload-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    let config_text = production_config_with_prerequisites(&directory)?;
    fs::write(&config, &config_text)?;
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
    let initial = read_status(&socket)?;
    assert!(initial.contains("\"log_level\":\"info\""));
    assert!(initial.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(initial.contains("\"effect_gate\":\"closed\""));

    fs::write(
        &config,
        config_text.replace(
            "automatic_promotion = true",
            "automatic_promotion = true\nlog_level = \"debug\"",
        ),
    )?;
    send_signal(child.id(), "-HUP")?;
    let reloaded = wait_for_status(&socket, "\"log_level\":\"debug\"")?;
    assert!(reloaded.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(reloaded.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    fs::write(
        &config,
        config_text
            .replace(
                "automatic_promotion = true",
                "automatic_promotion = true\nlog_level = \"debug\"",
            )
            .replace("cluster_id = \"prod-cluster\"", "cluster_id = \"other\""),
    )?;
    send_signal(child.id(), "-HUP")?;
    thread::sleep(Duration::from_millis(200));
    let refused = read_status(&socket)?;
    assert!(refused.contains("\"log_level\":\"debug\""));
    assert!(refused.contains("\"cluster_id\":\"prod-cluster\""));
    assert!(refused.contains("\"effect_gate\":\"closed\""));
    assert!(child.try_wait()?.is_none());

    send_signal(child.id(), "-TERM")?;
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(stdout.contains("DAEMON_STOPPED_EFFECT_CLOSED"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_pings_systemd_watchdog_without_ready_state() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-agent-watchdog-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, production_config_with_prerequisites(&directory)?)?;
    let notify_socket = directory.join("notify.sock");
    let listener = std::os::unix::net::UnixDatagram::bind(&notify_socket)?;
    listener.set_read_timeout(Some(Duration::from_millis(500)))?;

    let child = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .env("NOTIFY_SOCKET", &notify_socket)
        .env("WATCHDOG_USEC", "100000")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut buf = [0_u8; 128];
    let (len, _) = listener.recv_from(&mut buf)?;
    let ping = std::str::from_utf8(&buf[..len])?;
    assert_eq!(ping.trim(), "WATCHDOG=1");
    assert!(!ping.contains("READY=1"));

    send_signal(child.id(), "-TERM")?;
    let output = child.wait_with_output()?;
    assert!(output.status.success());
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_restarts_effect_closed_after_sigkill() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-sigkill-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, production_config_with_prerequisites(&directory)?)?;
    let socket = directory.join("status.sock");

    let mut first = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut first)?;
    let first_status = read_status(&socket)?;
    assert!(first_status.contains("\"effect_gate\":\"closed\""));
    assert!(first_status.contains("\"authority_enabled\":false"));
    send_signal(first.id(), "-KILL")?;
    let first_output = first.wait_with_output()?;
    assert!(!first_output.status.success());
    let _ = fs::remove_file(&socket);

    let mut second = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut second)?;
    let second_status = read_status(&socket)?;
    assert!(second_status.contains("\"effect_gate\":\"closed\""));
    assert!(second_status.contains("\"authority_enabled\":false"));
    assert!(!second_status.contains("READY=1"));
    send_signal(second.id(), "-TERM")?;
    let output = second.wait_with_output()?;
    let stdout = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(stdout.contains("DAEMON_STOPPED_EFFECT_CLOSED"));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_refuses_second_process_on_the_same_store() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-owner-lock-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, production_config_with_prerequisites(&directory)?)?;
    let socket = directory.join("status.sock");

    let mut first = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .args(["--status-socket"])
        .arg(&socket)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    wait_for_socket(&socket, &mut first)?;

    let second = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8(second.stderr)?;
    assert!(!second.status.success());
    assert!(stderr.contains("OWNER_LOCK_REFUSED"));
    assert!(stderr.contains("\"effect_gate\":\"closed\""));
    assert!(first.try_wait()?.is_none());

    send_signal(first.id(), "-TERM")?;
    let output = first.wait_with_output()?;
    assert!(output.status.success());
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_refuses_stored_boot_identity_change() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-boot-change-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, production_config_with_prerequisites(&directory)?)?;
    let boot_record = directory.join("store").join("boot.id");
    fs::write(&boot_record, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")?;
    fs::set_permissions(&boot_record, fs::Permissions::from_mode(0o600))?;

    let output = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(stderr.contains("BOOT_IDENTITY_CHANGED"));
    assert!(stderr.contains("\"effect_gate\":\"closed\""));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

#[test]
fn production_daemon_refuses_all_zero_signing_key() -> Result<(), Box<dyn Error>> {
    let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "quorumarc-production-zero-key-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory)?;
    let config = directory.join("agent.toml");
    fs::write(&config, production_config_with_prerequisites(&directory)?)?;
    fs::write(directory.join("node.seed"), [0_u8; 32])?;
    fs::set_permissions(
        directory.join("node.seed"),
        fs::Permissions::from_mode(0o600),
    )?;

    let output = Command::new(env!("CARGO_BIN_EXE_quorumarc-agent"))
        .args(["daemon", "--config"])
        .arg(&config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    let stderr = String::from_utf8(output.stderr)?;
    assert!(!output.status.success());
    assert!(stderr.contains("CONFIG_SIGNING_KEY_UNAVAILABLE"));
    assert!(stderr.contains("\"effect_gate\":\"closed\""));
    let _ = fs::remove_dir_all(directory);
    Ok(())
}

fn production_config_with_prerequisites(
    directory: &std::path::Path,
) -> Result<String, Box<dyn Error>> {
    let store = directory.join("store");
    let key = directory.join("node.seed");
    fs::create_dir(&store)?;
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700))?;
    fs::write(&key, [7_u8; 32])?;
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
    Ok(PRODUCTION_CONFIG
        .replace(
            "/var/lib/quorumarc/authority",
            store.to_str().ok_or("utf8")?,
        )
        .replace(
            "/etc/quorumarc/secrets/node-a.seed",
            key.to_str().ok_or("utf8")?,
        ))
}

fn send_signal(pid: u32, signal: &str) -> Result<(), Box<dyn Error>> {
    let status = Command::new("kill")
        .args([signal, &pid.to_string()])
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err("signal failed".into())
    }
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

fn wait_for_socket(path: &std::path::Path, child: &mut Child) -> Result<(), Box<dyn Error>> {
    for _ in 0..50 {
        if child.try_wait()?.is_some() {
            return Err("daemon exited before status socket".into());
        }
        if UnixStream::connect(path).is_ok() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("status socket was not created".into())
}
