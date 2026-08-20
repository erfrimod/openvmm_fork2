# HclNetworkVFManagerWorker Unit Test Plan

## Status

Proposed plan for adding deterministic unit coverage to
`HclNetworkVFManagerWorker`, with initial emphasis on VTL0 VF operations while
the VTL2 device is absent.

## Problem

`HclNetworkVFManagerWorker` combines three responsibilities:

1. It receives events from manager messages, VPCI, uevent, MANA reset
   notifications, and retry timers.
2. It decides how VTL0 and VTL2 lifecycle state should change.
3. It performs effects through MANA, VPCI, endpoints, GET, and saved state.

The lifecycle decisions are suitable for unit testing, but constructing the
worker currently requires live instances of concrete types such as
`ManaDevice<VfioDevice>`, `HclVpciBusControl`, DMA clients, and the uevent
callback handler. A test-only worker constructor would therefore either need
real ambient infrastructure or would make many production fields optional.

The existing `process_vf_manager_message` helper is a useful dispatch boundary,
but it does not solve the construction problem. The VTL2 device state and
reconfiguration backoff also remain local to `run`, so tests cannot directly
drive all lifecycle transitions.

## Goals

- Unit test VTL0 add, remove, hide, unhide, and revoke decisions for every VTL2
  presence state relevant to this change.
- Unit test duplicate and shutdown-gated operations.
- Unit test VPCI and uevent state transitions without requiring real VPCI or
  uevent sources.
- Assert both resulting logical state and requested side effects.
- Keep production ownership of MANA, VPCI, endpoint, and callback resources
  explicit.
- Make the first change small enough to review as part of the VTL0/VTL2 safety
  work.

## Non-Goals

- Running the complete merged-stream `run` loop in unit tests.
- Emulating a MANA device or VFIO device.
- Replacing existing VPCI, endpoint, GET, or uevent APIs with test-specific
  interfaces.
- Testing Linux sysfs or uevent delivery in a unit test.
- Testing MANA startup, shutdown, save, or endpoint packet flow in the first
  phase.

## Recommended Design

Separate lifecycle policy from effect execution. VPCI, uevent, manager
messages, reset notifications, and timers should be normalized into internal
events. A resource-free state object should consume those events and return the
effects that the concrete worker must perform.

The exact names can change during implementation, but the intended boundary is:

```rust
struct VfManagerRuntimeState {
    shutdown_active: bool,
    vtl2_device_state: Vtl2DeviceState,
    vf_reconfig_backoff: Option<VfReconfigBackoff>,
    vtl0_state: Vtl0LogicalState,
    offered_to_guest: bool,
    guest_vtl0_vfid: Option<u32>,
}

enum VfManagerEvent {
    AddVtl0,
    RemoveVtl0,
    UpdateVtl0 { vfid: Option<u32> },
    SetVtl0Hidden(bool),
    Vtl2Enumerated,
    Vtl2Arrived { surprise: bool },
    Vtl2Removed { surprise: bool },
    Reconfigure { revoke_vtl0: bool },
    ReconfigureRestart,
    ShutdownBegin { remove_vtl0: bool },
}

enum VfManagerAction {
    OfferVtl0,
    NotifyVtl0Arrival,
    NotifyAndRevokeVtl0,
    ForceSyntheticDatapath,
    StartVtl2 { update_binding: bool },
    StopVtl2,
    UpdateVtl2Binding(bool),
    ScheduleReconfigureRetry,
}
```

The transition entrypoint should be synchronous and deterministic:

```rust
fn transition(&mut self, event: VfManagerEvent) -> Vec<VfManagerAction>;
```

The production worker will continue to own concrete resources. It will map
incoming signals to `VfManagerEvent`, call `transition`, and execute the
returned actions using its existing async helper methods.

The state type and transition method should be normal private production code,
not `#[cfg(test)]` code. Unit tests in the same module can call the private
entrypoint directly. A test-only snapshot helper may be added if direct state
assertions become noisy, but no test-only event path should duplicate production
decision logic.

### VTL0 Control Ownership

`Vtl0Bus` currently combines logical state with ownership of an
`HclVpciBusControl`. Avoid cloning, fabricating, or placing this control in the
resource-free state machine.

Split the concepts at the worker boundary:

- Logical state records visible/hidden and present/not-present state plus the
  VTL0 VF ID.
- The worker retains the optional concrete `HclVpciBusControl` needed to offer
  or revoke the device.
- An action identifies which effect is required; the worker selects the current
  or displaced bus control when executing it.

This separation must preserve the existing removal behavior: when a VTL0 bus is
removed, the displaced control remains available until notification and revoke
have completed.

### Effect Interfaces

Do not introduce interfaces for all dependencies in the first phase. VPCI and
uevent are event sources and can be bypassed by injecting normalized events.
Endpoint and MANA calls are effects and can initially be verified by asserting
the returned `VfManagerAction` values.

If later tests need to execute effects and inject asynchronous failures, add one
narrow effect interface around worker operations rather than one interface per
underlying component:

```rust
#[async_trait]
trait VfManagerEffects {
    async fn offer_vtl0(&mut self) -> anyhow::Result<()>;
    async fn notify_vtl0_removal(&mut self) -> anyhow::Result<()>;
    async fn revoke_vtl0(&mut self) -> anyhow::Result<()>;
    async fn force_synthetic_datapath(&mut self) -> anyhow::Result<()>;
    async fn start_vtl2(&mut self, update_binding: bool) -> anyhow::Result<()>;
    async fn stop_vtl2(&mut self);
    async fn update_vtl2_binding(&mut self, bound: bool) -> anyhow::Result<()>;
}
```

Only add this trait when a test requires behavior beyond state and action
verification. MANA construction may instead receive its own factory interface
later, following the existing NVMe manager spawner pattern.

## Implementation Steps

### Phase 1: Extract the Transition Policy

1. Move `vtl2_device_state` and `vf_reconfig_backoff` out of local variables in
   `run` and into a resource-free runtime state object.
2. Add logical VTL0 visibility, presence, offered state, and guest-visible VF ID
   to that state object.
3. Move `NextWorkItem` out of `run` and replace it, or map it, with an internal
   `VfManagerEvent` type.
4. Extract the state mutation and effect selection from the `run` match and the
   VTL0 update/hide paths into `transition`.
5. Keep tracing, RPC completion, timeout handling, and concrete device calls in
   `HclNetworkVFManagerWorker`.
6. Add an action executor that delegates to the existing helpers such as
   `add_vtl0_vf`, `try_notify_guest_and_revoke_vtl0_vf`,
   `startup_vtl2_device`, and `shutdown_vtl2_device`.
7. Preserve ordering where it is observable, especially clearing the offered
   bit before guest notification and retaining a displaced VTL0 bus control
   until revoke completes.

### Phase 2: Add Focused Unit Tests

Add a `#[cfg(test)] mod tests` in `netvsp.rs` using
`test_with_tracing::test`. Keep tests synchronous unless action execution is
being tested.

Create a small fixture that initializes only `VfManagerRuntimeState`, applies an
event, and returns both the new state and actions. Use table-driven cases where
the expected behavior is a state matrix.

### Phase 3: Optional Effect Tests

Add the narrow `VfManagerEffects` boundary only if coverage is needed for:

- notification failure forcing the synthetic datapath;
- revoke failure or timeout behavior;
- MANA startup failure and retry scheduling;
- bind-state update suppression for surprise add/remove;
- ordering between notification, endpoint fallback, and revoke.

Use a recording fake that stores calls and configurable results. Do not model
VPCI, MANA, or endpoints more deeply than the behavior observed by the worker.

## Initial Test Matrix

### VTL0 Update

| Initial VTL2 | Initial VTL0 | Incoming VTL0 | Offered | Expected state/action |
| --- | --- | --- | --- | --- |
| Present | Not present | Present | No | Record VF ID and notify arrival |
| Missing | Not present | Present | No | Stage present VF; no arrival or offer |
| Present | Present | Removed | Yes | Clear guest VF ID; notify and revoke |
| Missing | Present | Removed | Yes | Clear guest VF ID; notify and revoke without endpoint fallback |
| Missing | Present | Removed | No | Clear state; no duplicate revoke |
| Any | Hidden/not present | Present | No | Become hidden/present; no arrival |
| Any | Hidden/present | Removed | Any | Become hidden/not present; no guest action |

### Hide and Unhide

| Initial VTL2 | Initial VTL0 | Request | Expected state/action |
| --- | --- | --- | --- |
| Present | Visible/present | Hide | Clear guest VF ID; notify and revoke; retain hidden control |
| Missing | Visible/present | Hide | Clear guest VF ID; notify and revoke without endpoint fallback |
| Any | Visible/not present | Hide | Become hidden/not present |
| Present | Hidden/present | Unhide | Become visible/present and notify arrival |
| Missing | Hidden/present | Unhide | Become visible/present, staged without arrival |
| Any | Hidden/not present | Unhide | Become visible/not present |
| Any | Already requested state | Repeat request | No duplicate action |

### Offer and Remove Messages

- `AddVtl0VF` offers only when VTL2 is present, VTL0 is visible/present, and the
  VF is not already offered.
- `AddVtl0VF` while VTL2 is missing produces no offer action.
- `RemoveVtl0VF` revokes an offered visible VF even when VTL2 is missing.
- Repeated remove requests produce no additional notification or revoke.
- Manager requests that are gated during shutdown do not mutate lifecycle
  state.

### VTL2 Events

- `Missing + Vtl2Enumerated` becomes `DeviceEnumerated`.
- Enumeration in any other state is ignored.
- An expected arrival requests startup with host binding notification.
- A surprise arrival requests startup without host binding notification.
- An expected removal requests VTL0 removal, VTL2 shutdown, and an unbound
  update.
- A surprise removal requests VTL0 removal and VTL2 shutdown without an unbound
  update.
- VTL2 removal cancels outstanding reconfiguration backoff.

### Reconfiguration

- Reconfiguration starts only from `Present` and outside shutdown.
- A requested VTL0 revoke occurs before VTL2 shutdown.
- The first failure schedules the expected initial backoff.
- Subsequent failures double the delay up to `RECONFIG_MAX_SLEEP`.
- Success returns to `Present` and clears backoff.
- Exhaustion returns to `Missing` and clears backoff.
- Shutdown cancels a pending restart.

## Validation

During implementation, validate the smallest affected slice after each step:

1. `cargo check -p underhill_core`
2. `cargo clippy --all-targets -p underhill_core`
3. `cargo doc --no-deps -p underhill_core`
4. `cargo nextest run --profile agent -p underhill_core`
5. `cargo xtask fmt --fix`

Run formatting last. If the crate package name differs from the directory name,
use the package name declared in `openhcl/underhill_core/Cargo.toml`.

## Risks and Mitigations

### State Duplication

Keeping logical state in the transition object while retaining concrete handles
in the worker can create two sources of truth. Centralize every lifecycle
mutation in `transition`, and add debug assertions at the executor boundary that
logical presence agrees with concrete control presence.

### Effect Ordering

Returning an unordered collection of effects could change observable behavior.
Use an ordered action list or a more specific compound action such as
`NotifyAndRevokeVtl0`. Add tests for ordering-sensitive transitions.

### Over-Abstraction

A trait for each external component would increase production complexity
without improving transition coverage. Begin with normalized events and action
assertions. Introduce an async effect trait or MANA factory only for concrete
failure-path tests.

### Scope Growth

The complete worker includes packet capture, save/restore, endpoint lifecycle,
and MANA initialization. Keep the initial patch centered on VTL0/VTL2 lifecycle
decisions touched by the current change. Add the remaining surfaces in separate
follow-up work.

## Acceptance Criteria

- The VTL0/VTL2 decision matrix can be tested without constructing MANA, VFIO,
  GET, VPCI, DMA, endpoint, or uevent objects.
- Production and tests call the same transition implementation.
- VTL0 removal while VTL2 is missing is covered and requests revoke without
  requesting endpoint datapath fallback.
- VTL0 addition while VTL2 is missing is staged and does not request an offer or
  arrival notification.
- Hidden VTL0 transitions are covered for both present and missing VTL2 states.
- Duplicate removals and shutdown-gated messages are covered.
- Existing worker behavior remains unchanged outside the explicitly corrected
  VTL0/VTL2-absent cases.
- The `underhill_core` check, clippy, docs, unit tests, and formatting validations
  pass.
