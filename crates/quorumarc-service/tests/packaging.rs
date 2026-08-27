#![allow(clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

fn packaging_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging")
}

fn read_unit(name: &str) -> String {
    fs::read_to_string(packaging_root().join("systemd").join(name)).expect("unit file")
}

fn read_debian(name: &str) -> String {
    fs::read_to_string(packaging_root().join("debian").join(name)).expect("debian file")
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
    assert!(unit.contains("Type=simple"));
    assert!(unit.contains("NotifyAccess=main"));
    assert!(unit.contains("WatchdogSec=30s"));
    assert!(!unit.contains("READY=1"));
    assert!(!unit.contains("--allow-"));
    assert!(!unit.contains("EffectGateExpired"));
}

#[test]
fn witness_unit_is_sandboxed_and_does_not_share_data_host_paths() {
    let unit = read_unit("quorumarc-witness.service");
    assert!(unit.contains("User=quorumarc-witness"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("Type=simple"));
    assert!(unit.contains("NotifyAccess=main"));
    assert!(unit.contains("WatchdogSec=30s"));
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

#[test]
fn debian_packaging_declares_agent_and_witness_packages() {
    let control = read_debian("control");
    assert!(control.contains("Package: quorumarc-agent"));
    assert!(control.contains("Package: quorumarc-witness"));
    assert!(control.contains("Architecture: linux-any"));
    assert!(control.contains("Depends: ${shlibs:Depends}, ${misc:Depends}"));
    let rules = read_debian("rules");
    assert!(rules.contains("override_dh_auto_test"));
    let conffiles = read_debian("conffiles");
    assert!(conffiles.contains("/etc/quorumarc-agent/agent.toml"));
    assert!(conffiles.contains("/etc/quorumarc-witness/witness.toml"));
}
