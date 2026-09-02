use crate::config::ProductionConfig;

/// Renders low-cardinality Prometheus metrics without identities, paths, or credentials.
#[must_use]
pub fn prometheus_text(
    config: &ProductionConfig,
    effect_gate: &str,
    authority_enabled: u8,
    uptime_ms: u64,
    last_committed_index: Option<u64>,
) -> String {
    let effect_gate_open = u8::from(effect_gate == "open");
    let last_commit = last_committed_index.unwrap_or(0);
    format!(
        "# TYPE quorumarc_effect_gate_open gauge\nquorumarc_effect_gate_open {effect_gate_open}\n\
# TYPE quorumarc_authority_enabled gauge\nquorumarc_authority_enabled {authority_enabled}\n\
# TYPE quorumarc_members gauge\nquorumarc_members {}\n\
# TYPE quorumarc_uptime_ms gauge\nquorumarc_uptime_ms {uptime_ms}\n\
# TYPE quorumarc_last_committed_index gauge\nquorumarc_last_committed_index {last_commit}\n",
        config.members().len()
    )
}
