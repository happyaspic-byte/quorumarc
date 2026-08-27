#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

fn packaging_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging")
}

fn read_unit(name: &str) -> String {
    fs::read_to_string(packaging_root().join("systemd").join(name)).expect("unit file")
}

#[test]
fn agent_unit_is_sandboxed_and_starts_closed_daemon() {
    let unit = read_unit("quorumarc-agent.service");
    assert!(unit.contains("User=quorumarc"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(unit.contains("MemoryDenyWriteExecute=yes"));
    assert!(unit.contains("RestrictRealtime=yes"));
    assert!(unit.contains("ProtectKernelTunables=yes"));
    assert!(unit.contains("CapabilityBoundingSet="));
    assert!(
        unit.contains(
            "ExecStart=/usr/bin/quorumarc-agent daemon --config /etc/quorumarc-agent/agent.toml --status-socket /run/quorumarc/status.sock"
        )
    );
    assert!(!unit.contains("--allow-"));
    assert!(!unit.contains("EffectGateExpired"));
}

#[test]
fn witness_unit_is_sandboxed_and_does_not_share_data_host_paths() {
    let unit = read_unit("quorumarc-witness.service");
    assert!(unit.contains("User=quorumarc-witness"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains(
        "ExecStart=/usr/bin/quorumarc-witness daemon --config /etc/quorumarc-witness/witness.toml"
    ));
    assert!(!unit.contains("/var/lib/quorumarc/authority"));
    assert!(!unit.contains("172.30.1.84"));
}

#[test]
fn sysusers_and_tmpfiles_create_least_privilege_paths() {
    let users =
        fs::read_to_string(packaging_root().join("sysusers.d/quorumarc.conf")).expect("sysusers");
    let tmpfiles =
        fs::read_to_string(packaging_root().join("tmpfiles.d/quorumarc.conf")).expect("tmpfiles");
    assert!(users.contains("u quorumarc "));
    assert!(users.contains("u quorumarc-witness "));
    assert!(tmpfiles.contains("d /var/lib/quorumarc 0750 quorumarc quorumarc"));
    assert!(tmpfiles.contains("d /run/quorumarc 0750 quorumarc quorumarc"));
    assert!(
        tmpfiles.contains("d /var/lib/quorumarc-witness 0750 quorumarc-witness quorumarc-witness")
    );
    assert!(tmpfiles.contains("d /etc/quorumarc-agent 0750 root quorumarc"));
    assert!(tmpfiles.contains("d /etc/quorumarc-witness 0750 root quorumarc-witness"));
}
