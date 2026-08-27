use quorumarc_service::controller::{
    PlannedSwitch, PlannedSwitchError, PlannedSwitchStep, SwitchRole,
};

#[test]
fn planned_switch_advances_only_through_closed_effects_until_certified() {
    let mut switch = PlannedSwitch::new(SwitchRole::NodeA, SwitchRole::NodeB);
    assert_eq!(switch.step(), PlannedSwitchStep::Prepare);
    assert_eq!(switch.advance(PlannedSwitchStep::CatchUp), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::HealthVerify), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::Drain), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::CloseOldEffects), Ok(()));
    assert!(!switch.effects_open());
    assert_eq!(switch.advance(PlannedSwitchStep::Certify), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::PersistActivation), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::OpenNewEffects), Ok(()));
    assert_eq!(switch.advance(PlannedSwitchStep::Receipt), Ok(()));
    assert_eq!(switch.step(), PlannedSwitchStep::Complete);
}

#[test]
fn planned_switch_halts_closed_on_ambiguous_or_skipped_step() {
    let mut switch = PlannedSwitch::new(SwitchRole::NodeA, SwitchRole::NodeB);
    assert_eq!(
        switch.advance(PlannedSwitchStep::OpenNewEffects),
        Err(PlannedSwitchError::Ambiguous)
    );
    assert!(!switch.effects_open());
    assert_eq!(switch.step(), PlannedSwitchStep::Halted);
}
