// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for the netvsp save/restore code path.
//!
//! The `save()` / `restore()` implementation processes data from the
//! host/root — a trust boundary in OpenHCL — and includes complex state-
//! machine reconstruction for VF state, pending TX completions, RSS config,
//! and GPADL remapping.
//!
//! ## Two complementary modes
//!
//! - **`ArbitraryRestore`**: construct a completely arbitrary
//!   [`saved_state::SavedState`], encode it, and call `restore()` without any
//!   prior live negotiation.  Exercises all error branches with structurally
//!   valid but semantically impossible states (unknown GPADL IDs, unsupported
//!   versions, invalid VF state, oversized channel lists, …).
//!
//! - **`SnapshotMutate`**: negotiate to the Ready state, take a live snapshot
//!   via `save()`, parse the snapshot into a `SavedState`, apply fuzzer-driven
//!   *structural* mutations (which keep GPADL IDs valid so `restore_state()`
//!   proceeds past the GPADL-lookup checks), then call `restore()`.  Exercises
//!   the deeper state-machine reconstruction logic where most of the complex
//!   code lives.

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::DATA_PAGES;
use fuzz_helpers::FuzzGuestOsId;
use fuzz_helpers::PageLayout;
use fuzz_helpers::RingFullError;
use fuzz_helpers::build_structured_rndis_packet;
use fuzz_helpers::drain_queue_async;
use fuzz_helpers::negotiate_to_ready;
use fuzz_helpers::nic_setup::FuzzNicConfig;
use fuzz_helpers::nic_setup::FuzzNicSetup;
use fuzz_helpers::nic_setup::NicSetupHandle;
use fuzz_helpers::nic_setup::create_nic_with_channel;
use fuzz_helpers::send_inband_nvsp;
use fuzz_helpers::send_rndis_via_direct_path;
use guestmem::GuestMemory;
use netvsp::protocol;
use netvsp::saved_state;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmcore::save_restore::SavedStateBlob;
use xtask_fuzz::fuzz_eprintln;
use xtask_fuzz::fuzz_target;

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 1,
    data_pages: DATA_PAGES,
};

/// A single action to run after a successful restore + start.
#[derive(Arbitrary, Debug)]
enum PostRestoreAction {
    /// Send an RNDIS data packet to exercise the TX path with restored state.
    SendRndisPacket {
        ppi_bytes: Vec<u8>,
        frame_data: Vec<u8>,
    },
    /// Send an NVSP control message post-restore.
    SendControlMessage { message_type: u32, payload: Vec<u8> },
}

/// Two complementary fuzzing modes for `save()` / `restore()`.
#[derive(Arbitrary, Debug)]
enum FuzzMode {
    /// Entirely arbitrary `SavedState`: no prior negotiation, immediate
    /// `restore()`. Reaches all error-handling branches (unknown GPADL IDs,
    /// unsupported versions, absurd channel counts, …).
    ArbitraryRestore {
        state: saved_state::SavedState,
        /// When `true`, patch the GPADL IDs in `state` to the real values
        /// from the fuzz setup before calling `restore()`. This lets GPADL
        /// lookup succeed so `restore_state()` proceeds further into the
        /// `ReadyPrimary` (or `Init`) reconstruction code rather than
        /// returning early on a lookup failure.
        use_real_gpadl_ids: bool,
    },
    /// Live snapshot then wholesale `ReadyPrimary` replacement before
    /// `restore()`. The fuzzed `ReadyPrimary` has its GPADL IDs patched to
    /// the real values so `restore_state()` proceeds past GPADL-lookup
    /// checks and into deeper state-machine reconstruction code.
    SnapshotMutate {
        ready: Box<saved_state::ReadyPrimary>,
        /// If `true` and `restore()` succeeds, call `start()` and drain the
        /// queue to exercise the restarted state machine.
        restart_after_restore: bool,
        /// Optional single action to run after a successful restart.
        post_restore_action: Option<PostRestoreAction>,
    },
}

fn do_fuzz(input: &[u8]) {
    xtask_fuzz::init_tracing_if_repro();
    let mut u = Unstructured::new(input);

    // Fuzz-select the guest OS identity so this target also covers all
    // `can_use_ring_opt` branches.
    let mut config = FuzzNicConfig::default();
    if let Ok(fuzz_os) = u.arbitrary::<FuzzGuestOsId>() {
        config.get_guest_os_id = fuzz_os.to_hv_guest_os_id();
    }

    pal_async::DefaultPool::run_with(async |driver| {
        // Build the NIC internals but do NOT start the channel yet; the fuzz
        // mode may call restore() before start(), so we control sequencing.
        let (handle, setup) = match create_nic_with_channel(&driver, &LAYOUT, config).await {
            Ok(pair) => pair,
            Err(_) => return,
        };

        let mode = match u.arbitrary::<FuzzMode>() {
            Ok(m) => m,
            Err(_) => {
                handle.cleanup().await;
                return;
            }
        };

        let fuzz_result = mesh::CancelContext::new()
            .with_timeout(std::time::Duration::from_millis(500))
            .until_cancelled(run_mode(&mut u, handle, setup, mode))
            .await;

        match fuzz_result {
            Ok(Ok(())) => {
                fuzz_eprintln!("fuzz: test case exhausted arbitrary data");
            }
            Ok(Err(e)) => {
                if e.downcast_ref::<arbitrary::Error>().is_some() {
                    fuzz_eprintln!("fuzz: arbitrary data exhausted: {e:#}");
                } else if e.downcast_ref::<RingFullError>().is_some() {
                    fuzz_eprintln!("fuzz: ring full (backpressure), stopping");
                } else {
                    panic!("fuzz: action error: {e:#}");
                }
            }
            Err(_) => {
                panic!("fuzz: timed out after 500ms");
            }
        }
    });
}

fuzz_target!(|input: &[u8]| do_fuzz(input));

async fn run_mode(
    u: &mut Unstructured<'_>,
    handle: NicSetupHandle,
    setup: FuzzNicSetup,
    mode: FuzzMode,
) -> anyhow::Result<()> {
    let result = run_mode_inner(u, &handle, setup, mode).await;
    handle.cleanup().await;
    result
}

async fn run_mode_inner(
    u: &mut Unstructured<'_>,
    handle: &NicSetupHandle,
    setup: FuzzNicSetup,
    mode: FuzzMode,
) -> anyhow::Result<()> {
    let FuzzNicSetup {
        mut queue,
        mem,
        recv_buf_gpadl_id,
        send_buf_gpadl_id,
        ..
    } = setup;

    match mode {
        FuzzMode::ArbitraryRestore {
            mut state,
            use_real_gpadl_ids,
        } => {
            // Optionally patch GPADL IDs so the restore proceeds into deeper
            // branches rather than failing on GPADL lookup.
            if use_real_gpadl_ids {
                patch_state_gpadl_ids(&mut state, recv_buf_gpadl_id, send_buf_gpadl_id);
            }

            let blob = SavedStateBlob::new(state);

            // The channel is in "not started" state — restore() can be called
            // directly without stop() because the device task hasn't started.
            // Must not panic regardless of whether restore returns Ok or Err.
            let _ = handle.channel.restore(blob).await;
        }

        FuzzMode::SnapshotMutate {
            ready,
            restart_after_restore,
            post_restore_action,
        } => {
            // Advance to Ready so save() captures a meaningful blob.
            let mut tid = 1u64;
            handle.channel.start();
            negotiate_to_ready(&mut queue, &mut tid, recv_buf_gpadl_id, send_buf_gpadl_id).await?;

            // Stop the channel before save/restore.
            handle.channel.stop().await;

            if let Some(blob) = handle.channel.save().await? {
                if let Ok(mut state) = blob.parse::<saved_state::SavedState>() {
                    // Replace the ReadyPrimary with the fuzzed one, then
                    // patch GPADL IDs so restore_state can look them up.
                    if let Some(open) = state.open.as_mut() {
                        if let saved_state::Primary::Ready(r) = &mut open.primary {
                            *r = *ready;
                        }
                    }
                    patch_state_gpadl_ids(&mut state, recv_buf_gpadl_id, send_buf_gpadl_id);
                    let mutated_blob = SavedStateBlob::new(state);

                    // Restore from the mutated blob. Must not panic.
                    let restore_ok = handle.channel.restore(mutated_blob).await.is_ok();

                    if restore_ok && restart_after_restore {
                        handle.channel.start();
                        // Yield so the coordinator/worker tasks can restart.
                        fuzz_helpers::yield_to_executor(5).await;
                        // Brief drain to exercise the restarted state machine.
                        drain_queue_async(&mut queue).await;

                        // Run a single post-restore action if provided.
                        if let Some(action) = &post_restore_action {
                            execute_post_restore_action(action, &mut queue, &mem, &mut tid).await?;
                        }

                        handle.channel.stop().await;
                    }
                }
            }
        }
    }

    // Suppress unused-variable warning when `u` has nothing left to consume.
    let _ = u;
    Ok(())
}

/// Execute a single post-restore action against the restarted NIC.
async fn execute_post_restore_action(
    action: &PostRestoreAction,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    tid: &mut u64,
) -> anyhow::Result<()> {
    fuzz_eprintln!("action: {action:?}");
    match action {
        PostRestoreAction::SendRndisPacket {
            ppi_bytes,
            frame_data,
        } => {
            let rndis_buf = build_structured_rndis_packet(ppi_bytes, frame_data);
            send_rndis_via_direct_path(
                queue,
                mem,
                &rndis_buf,
                protocol::DATA_CHANNEL_TYPE,
                &LAYOUT,
                tid,
            )
            .await?;
            drain_queue_async(queue).await;
        }
        PostRestoreAction::SendControlMessage {
            message_type,
            payload,
        } => {
            send_inband_nvsp(queue, tid, *message_type, payload, true).await?;
            drain_queue_async(queue).await;
        }
    }
    Ok(())
}

/// Patch all GPADL ID fields in a `SavedState` to use the real recv/send
/// buffer GPADL IDs from the fuzz setup.  This is needed for
/// `ArbitraryRestore` mode when the fuzzer wants `restore_state()` to succeed
/// at GPADL lookup and proceed into deeper state-machine reconstruction.
fn patch_state_gpadl_ids(state: &mut saved_state::SavedState, recv: GpadlId, send: GpadlId) {
    let primary = match state.open.as_mut().map(|o| &mut o.primary) {
        Some(p) => p,
        None => return,
    };
    match primary {
        saved_state::Primary::Ready(r) => {
            r.receive_buffer.gpadl_id = recv;
            if let Some(sb) = &mut r.send_buffer {
                sb.gpadl_id = send;
            }
        }
        saved_state::Primary::Init(i) => {
            if let Some(rb) = &mut i.receive_buffer {
                rb.gpadl_id = recv;
            }
            if let Some(sb) = &mut i.send_buffer {
                sb.gpadl_id = send;
            }
        }
        saved_state::Primary::Version => {}
    }
}
