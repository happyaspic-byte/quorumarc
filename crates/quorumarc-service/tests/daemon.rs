use quorumarc_service::node::{DaemonReadiness, ProductionNode};

#[test]
fn incomplete_production_node_never_reports_ready_or_opens_effects() {
    let node = ProductionNode::effect_closed();
    assert_eq!(node.readiness(), DaemonReadiness::EffectClosed);
    assert_eq!(node.effect_gate_state(), "closed");
    assert!(!node.authority_enabled());
}
