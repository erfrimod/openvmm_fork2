// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Vtl2DeviceState;
use super::vf_manager_policy::VfManagerState;
use super::vf_manager_policy::VfManagerStateInconsistency;
use super::vf_manager_policy::Vtl0Action;
use super::vf_manager_policy::Vtl0State;
use test_with_tracing::test;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Vtl0BusState {
    NotPresent,
    Present,
    HiddenNotPresent,
    HiddenPresent,
}

const VTL0_BUS_STATES: [Vtl0BusState; 4] = [
    Vtl0BusState::NotPresent,
    Vtl0BusState::Present,
    Vtl0BusState::HiddenNotPresent,
    Vtl0BusState::HiddenPresent,
];

const VTL2_DEVICE_STATES: [Vtl2DeviceState; 4] = [
    Vtl2DeviceState::DeviceEnumerated,
    Vtl2DeviceState::Missing,
    Vtl2DeviceState::Present,
    Vtl2DeviceState::Reconfiguring,
];

fn state(
    shutdown_active: bool,
    vtl2_device_state: Vtl2DeviceState,
    bus: Vtl0BusState,
    offered_to_guest: bool,
) -> VfManagerState {
    let (present, hidden) = match bus {
        Vtl0BusState::NotPresent => (false, false),
        Vtl0BusState::Present => (true, false),
        Vtl0BusState::HiddenNotPresent => (false, true),
        Vtl0BusState::HiddenPresent => (true, true),
    };
    VfManagerState::new(
        shutdown_active,
        Vtl0State::new(present, hidden, offered_to_guest),
        vtl2_device_state,
    )
}

#[test]
fn add_vtl0() {
    for shutdown_active in [false, true] {
        for vtl2 in VTL2_DEVICE_STATES {
            for bus in VTL0_BUS_STATES {
                for offered_to_guest in [false, true] {
                    let expected = matches!(
                        (shutdown_active, vtl2, bus, offered_to_guest),
                        (
                            false,
                            Vtl2DeviceState::Present,
                            Vtl0BusState::Present,
                            false
                        )
                    );
                    let state = state(shutdown_active, vtl2, bus, offered_to_guest);
                    assert_eq!(state.should_add(), expected, "{state:?}");
                }
            }
        }
    }
}

#[test]
fn remove_vtl0() {
    for shutdown_active in [false, true] {
        for vtl2 in VTL2_DEVICE_STATES {
            for bus in VTL0_BUS_STATES {
                for offered_to_guest in [false, true] {
                    let expected = matches!(
                        (shutdown_active, bus, offered_to_guest),
                        (false, Vtl0BusState::Present, true)
                    );
                    let state = state(shutdown_active, vtl2, bus, offered_to_guest);
                    assert_eq!(state.should_remove(), expected, "{state:?}");
                }
            }
        }
    }
}

#[test]
fn inconsistent_vtl0_state() {
    use VfManagerStateInconsistency::{Vtl0OfferedWhileHidden, Vtl0OfferedWithoutBus};

    for bus in VTL0_BUS_STATES {
        for offered_to_guest in [false, true] {
            let expected = match (bus, offered_to_guest) {
                (Vtl0BusState::HiddenNotPresent | Vtl0BusState::HiddenPresent, true) => {
                    Some(Vtl0OfferedWhileHidden)
                }
                (Vtl0BusState::NotPresent, true) => Some(Vtl0OfferedWithoutBus),
                _ => None,
            };
            let state = state(false, Vtl2DeviceState::Present, bus, offered_to_guest);
            assert_eq!(state.inconsistency(), expected, "{state:?}");
        }
    }
}

#[test]
fn begin_shutdown() {
    let offered = state(false, Vtl2DeviceState::Present, Vtl0BusState::Present, true);
    assert!(offered.should_remove_for_shutdown(true));
    assert!(!offered.should_remove_for_shutdown(false));

    let shutdown = state(true, Vtl2DeviceState::Present, Vtl0BusState::Present, true);
    assert!(!shutdown.should_remove_for_shutdown(true));
}

#[test]
fn update_vtl0_bus() {
    for vtl2 in VTL2_DEVICE_STATES {
        for bus in VTL0_BUS_STATES {
            for offered_to_guest in [false, true] {
                let present = matches!(
                    bus,
                    Vtl0BusState::NotPresent | Vtl0BusState::HiddenNotPresent
                );
                let expected = match (bus, present, vtl2, offered_to_guest) {
                    (Vtl0BusState::NotPresent, true, Vtl2DeviceState::Present, _) => {
                        Some(Vtl0Action::NotifyArrival)
                    }
                    (Vtl0BusState::Present, false, _, true) => {
                        Some(Vtl0Action::NotifyRemovalAndRevoke)
                    }
                    _ => None,
                };
                let state = state(false, vtl2, bus, offered_to_guest);
                assert_eq!(state.bus_update_action(present), expected, "{state:?}");
            }
        }
    }
}

#[test]
fn change_vtl0_visibility() {
    for vtl2 in VTL2_DEVICE_STATES {
        for bus in VTL0_BUS_STATES {
            for offered_to_guest in [false, true] {
                for hidden in [false, true] {
                    let expected = match (bus, hidden, vtl2, offered_to_guest) {
                        (Vtl0BusState::Present, true, _, true) => {
                            Some(Vtl0Action::NotifyRemovalAndRevoke)
                        }
                        (Vtl0BusState::HiddenPresent, false, Vtl2DeviceState::Present, _) => {
                            Some(Vtl0Action::NotifyArrival)
                        }
                        _ => None,
                    };
                    let state = state(false, vtl2, bus, offered_to_guest);
                    assert_eq!(state.hidden_change_action(hidden), expected, "{state:?}");
                }
            }
        }
    }
}
