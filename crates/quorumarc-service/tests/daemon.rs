#![allow(clippy::expect_used)]

use std::thread;
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
fn shutdown_wait_blocks_until_request_and_then_unblocks() {
    let shutdown = ShutdownToken::new();
    let worker = shutdown.clone();
    let handle = thread::spawn(move || worker.wait());
    thread::sleep(Duration::from_millis(10));
    assert!(!handle.is_finished());
    shutdown.request();
    handle.join().expect("wait thread");
}

#[test]
fn effect_closed_daemon_stops_without_ever_becoming_ready() {
    let mut node = ProductionNode::effect_closed();
    let shutdown = ShutdownToken::new();
    shutdown.request();
    let report = node.run_until_shutdown(&shutdown);
    assert_eq!(report.initial, DaemonReadiness::EffectClosed);
    assert_eq!(report.final_state, DaemonReadiness::Stopped);
    assert!(!report.ever_ready);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}
