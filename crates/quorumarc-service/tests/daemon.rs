use std::time::Duration;

use quorumarc_service::node::{DaemonReadiness, ProductionNode};
use quorumarc_service::signal::ShutdownToken;

#[test]
fn incomplete_production_node_never_reports_ready_or_opens_effects() {
    let node = ProductionNode::effect_closed();
    assert_eq!(node.readiness(), DaemonReadiness::EffectClosed);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}

#[test]
fn effect_closed_daemon_stops_without_ever_becoming_ready() {
    let mut node = ProductionNode::effect_closed();
    let shutdown = ShutdownToken::new();
    shutdown.request();
    let report = node.run_until_shutdown(&shutdown, Duration::from_millis(1));
    assert_eq!(report.initial, DaemonReadiness::EffectClosed);
    assert_eq!(report.final_state, DaemonReadiness::Stopped);
    assert!(!report.ever_ready);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}
