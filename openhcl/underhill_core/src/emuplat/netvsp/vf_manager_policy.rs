// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::Vtl2DeviceState;

#[derive(Clone, Copy, Debug)]
pub(super) struct Vtl0State {
    bus_present: bool,
    bus_hidden: bool,
    offered_to_guest: bool,
}

impl Vtl0State {
    pub(super) fn new(bus_present: bool, bus_hidden: bool, offered_to_guest: bool) -> Self {
        Self {
            bus_present,
            bus_hidden,
            offered_to_guest,
        }
    }
}

/// An ephemeral snapshot of the state needed for one VF manager policy decision.
///
/// This captures the shutdown flag, VTL0 bus and guest-offer state, and VTL2
/// device state. The worker constructs it immediately before dispatching a
/// `NextWorkItem`, which is processed to completion before the next item is
/// polled. Consequently, worker-owned state cannot change while the item is
/// being handled.
///
/// The snapshot must not be retained across work items. It would become stale if
/// work items were processed concurrently or another component began mutating
/// guest state outside the worker loop.
#[derive(Clone, Copy, Debug)]
pub(super) struct VfManagerState {
    shutdown_active: bool,
    vtl0: Vtl0State,
    vtl2: Vtl2DeviceState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VfManagerStateInconsistency {
    Vtl0OfferedWhileHidden,
    Vtl0OfferedWithoutBus,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Vtl0Action {
    NotifyArrival,
    NotifyRemovalAndRevoke,
}

impl VfManagerState {
    pub(super) fn new(shutdown_active: bool, vtl0: Vtl0State, vtl2: Vtl2DeviceState) -> Self {
        Self {
            shutdown_active,
            vtl0,
            vtl2,
        }
    }

    pub(super) fn shutdown_active(&self) -> bool {
        self.shutdown_active
    }

    pub(super) fn inconsistency(&self) -> Option<VfManagerStateInconsistency> {
        if self.vtl0.offered_to_guest && self.vtl0.bus_hidden {
            Some(VfManagerStateInconsistency::Vtl0OfferedWhileHidden)
        } else if self.vtl0.offered_to_guest && !self.vtl0.bus_present {
            Some(VfManagerStateInconsistency::Vtl0OfferedWithoutBus)
        } else {
            None
        }
    }

    pub(super) fn vtl2_present(&self) -> bool {
        matches!(self.vtl2, Vtl2DeviceState::Present)
    }

    pub(super) fn vtl0_offered_to_guest(&self) -> bool {
        self.vtl0.offered_to_guest
    }

    pub(super) fn should_add(&self) -> bool {
        !self.shutdown_active
            && self.vtl2_present()
            && self.vtl0.bus_present
            && !self.vtl0.bus_hidden
            && !self.vtl0.offered_to_guest
    }

    pub(super) fn should_remove(&self) -> bool {
        !self.shutdown_active
            && self.vtl0.bus_present
            && !self.vtl0.bus_hidden
            && self.vtl0.offered_to_guest
    }

    pub(super) fn should_remove_for_shutdown(&self, remove_vtl0: bool) -> bool {
        remove_vtl0 && self.should_remove()
    }

    pub(super) fn bus_update_action(&self, present: bool) -> Option<Vtl0Action> {
        assert_ne!(self.vtl0.bus_present, present);
        if self.vtl0.bus_hidden {
            None
        } else if present {
            self.vtl2_present().then_some(Vtl0Action::NotifyArrival)
        } else {
            self.vtl0
                .offered_to_guest
                .then_some(Vtl0Action::NotifyRemovalAndRevoke)
        }
    }

    pub(super) fn hidden_change_action(&self, hidden: bool) -> Option<Vtl0Action> {
        if self.vtl0.bus_hidden == hidden {
            return None;
        }
        if !self.vtl0.bus_present {
            None
        } else if hidden {
            self.vtl0
                .offered_to_guest
                .then_some(Vtl0Action::NotifyRemovalAndRevoke)
        } else {
            self.vtl2_present().then_some(Vtl0Action::NotifyArrival)
        }
    }
}
