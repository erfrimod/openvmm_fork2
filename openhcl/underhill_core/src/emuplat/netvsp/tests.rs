// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::VfManagerState;
use super::Vtl0Action;
use super::Vtl0State;
use super::Vtl2DeviceState;
use test_with_tracing::test;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vtl0BusState {
    NotPresent,
    Present(()),
    HiddenNotPresent,
    HiddenPresent(()),
}

fn state(
    shutdown_active: bool,
    vtl2_device_state: Vtl2DeviceState,
    bus: Vtl0BusState,
    offered_to_guest: bool,
) -> VfManagerState {
    let (present, hidden) = match bus {
        Vtl0BusState::NotPresent => (false, false),
        Vtl0BusState::Present(()) => (true, false),
        Vtl0BusState::HiddenNotPresent => (false, true),
        Vtl0BusState::HiddenPresent(()) => (true, true),
    };
    VfManagerState {
        shutdown_active,
        vtl0: Vtl0State {
            bus_present: present,
            bus_hidden: hidden,
            offered_to_guest,
        },
        vtl2: vtl2_device_state,
    }
}

#[test]
fn add_vtl0() {
    for (name, state, expected) in [
        (
            "offer visible VTL0 while VTL2 is present",
            state(
                false,
                Vtl2DeviceState::Present,
                Vtl0BusState::Present(()),
                false,
            ),
            true,
        ),
        (
            "do not offer while VTL2 is enumerated",
            state(
                false,
                Vtl2DeviceState::DeviceEnumerated,
                Vtl0BusState::Present(()),
                false,
            ),
            false,
        ),
        (
            "do not offer while VTL2 is missing",
            state(
                false,
                Vtl2DeviceState::Missing,
                Vtl0BusState::Present(()),
                false,
            ),
            false,
        ),
        (
            "do not offer while VTL2 is reconfiguring",
            state(
                false,
                Vtl2DeviceState::Reconfiguring,
                Vtl0BusState::Present(()),
                false,
            ),
            false,
        ),
        (
            "do not offer absent VTL0",
            state(
                false,
                Vtl2DeviceState::Present,
                Vtl0BusState::NotPresent,
                false,
            ),
            false,
        ),
        (
            "do not offer VTL0 twice",
            state(
                false,
                Vtl2DeviceState::Present,
                Vtl0BusState::Present(()),
                true,
            ),
            false,
        ),
        (
            "do not offer during shutdown",
            state(
                true,
                Vtl2DeviceState::Present,
                Vtl0BusState::Present(()),
                false,
            ),
            false,
        ),
    ] {
        assert_eq!(state.should_add(), expected, "{name}: {state:?}");
    }
}

#[test]
fn remove_vtl0() {
    for (name, state, expected) in [
        (
            "remove offered VTL0 while VTL2 is present",
            state(
                false,
                Vtl2DeviceState::Present,
                Vtl0BusState::Present(()),
                true,
            ),
            true,
        ),
        (
            "remove offered VTL0 while VTL2 is missing",
            state(
                false,
                Vtl2DeviceState::Missing,
                Vtl0BusState::Present(()),
                true,
            ),
            true,
        ),
        (
            "do not remove VTL0 twice",
            state(
                false,
                Vtl2DeviceState::Missing,
                Vtl0BusState::Present(()),
                false,
            ),
            false,
        ),
        (
            "do not remove hidden VTL0",
            state(
                false,
                Vtl2DeviceState::Present,
                Vtl0BusState::HiddenPresent(()),
                true,
            ),
            false,
        ),
        (
            "do not remove during shutdown",
            state(
                true,
                Vtl2DeviceState::Present,
                Vtl0BusState::Present(()),
                true,
            ),
            false,
        ),
    ] {
        assert_eq!(state.should_remove(), expected, "{name}: {state:?}");
    }
}

#[test]
fn begin_shutdown() {
    let offered = state(
        false,
        Vtl2DeviceState::Present,
        Vtl0BusState::Present(()),
        true,
    );
    assert!(offered.should_remove_for_shutdown(true));
    assert!(!offered.should_remove_for_shutdown(false));

    let shutdown = state(
        true,
        Vtl2DeviceState::Present,
        Vtl0BusState::Present(()),
        true,
    );
    assert!(!shutdown.should_remove_for_shutdown(true));
}

fn assert_bus_update(state: &VfManagerState, present: bool, expected_action: Option<Vtl0Action>) {
    assert_eq!(state.bus_update_action(present), expected_action);
}

#[test]
fn update_visible_vtl0() {
    let absent = state(
        false,
        Vtl2DeviceState::Present,
        Vtl0BusState::NotPresent,
        false,
    );
    assert_bus_update(&absent, true, Some(Vtl0Action::NotifyArrival));

    let offered = state(
        false,
        Vtl2DeviceState::Present,
        Vtl0BusState::Present(()),
        true,
    );
    assert_bus_update(&offered, false, Some(Vtl0Action::NotifyRemovalAndRevoke));

    let missing = state(
        false,
        Vtl2DeviceState::Missing,
        Vtl0BusState::NotPresent,
        false,
    );
    assert_bus_update(&missing, true, None);
}

#[test]
fn hide_and_unhide_vtl0() {
    let visible = state(
        false,
        Vtl2DeviceState::Present,
        Vtl0BusState::Present(()),
        true,
    );
    assert_eq!(
        visible.hidden_change_action(true),
        Some(Vtl0Action::NotifyRemovalAndRevoke)
    );

    let hidden_missing = state(
        false,
        Vtl2DeviceState::Missing,
        Vtl0BusState::HiddenPresent(()),
        false,
    );
    assert_eq!(hidden_missing.hidden_change_action(false), None);

    let hidden_absent = state(
        false,
        Vtl2DeviceState::Present,
        Vtl0BusState::HiddenNotPresent,
        false,
    );
    assert_eq!(hidden_absent.hidden_change_action(false), None);
}
