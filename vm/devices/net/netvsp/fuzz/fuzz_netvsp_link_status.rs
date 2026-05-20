// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for link status change handling in NetVSP.
//!
//! This fuzzer exercises the coordinator link-status notification path by
//! injecting `EndpointAction::LinkStatusNotify` and
//! `EndpointAction::RestartRequired` events via a [`FuzzEndpoint`], while
//! interleaving normal NVSP control and data path operations.
//!
//! ## RNDIS protocol messages tested
//!
//! Indirectly exercised (host-to-guest, triggered by link events):
//! - `MESSAGE_TYPE_INDICATE_STATUS_MSG` with `STATUS_MEDIA_CONNECT` — link up
//! - `MESSAGE_TYPE_INDICATE_STATUS_MSG` with `STATUS_MEDIA_DISCONNECT` — link
//!   down
//!
//! ## Endpoint actions tested
//!
//! - `EndpointAction::LinkStatusNotify(true)` — link up notification
//! - `EndpointAction::LinkStatusNotify(false)` — link down notification
//! - `EndpointAction::RestartRequired` — restart signal

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::DATA_PAGES;
use fuzz_helpers::PageLayout;
use fuzz_helpers::build_structured_rndis_packet;
use fuzz_helpers::drain_queue_async;
use fuzz_helpers::endpoint::FuzzEndpoint;
use fuzz_helpers::endpoint::FuzzEndpointConfig;
use fuzz_helpers::negotiate_to_ready;
use fuzz_helpers::nic_setup::FuzzNicConfig;
use fuzz_helpers::rndis_initialize;
use fuzz_helpers::run_fuzz_loop_with_config;
use fuzz_helpers::send_rndis_via_direct_path;
use guestmem::GuestMemory;
use net_backend::EndpointAction;
use netvsp::protocol;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use xtask_fuzz::fuzz_eprintln;
use xtask_fuzz::fuzz_target;

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 1,
    data_pages: DATA_PAGES,
};

/// Actions the fuzzer can take to exercise link status handling.
#[derive(Arbitrary, Debug)]
enum LinkAction {
    /// Inject a link-up notification from the endpoint.
    LinkUp,
    /// Inject a link-down notification from the endpoint.
    LinkDown,
    /// Inject a `RestartRequired` action from the endpoint.
    RestartRequired,
    /// Send a structured RNDIS data packet via GpaDirect to exercise
    /// TX during link state transitions.
    SendRndisPacket {
        /// Fuzzed per-packet-info bytes.
        ppi_bytes: Vec<u8>,
        /// Fuzzed ethernet frame data.
        frame_data: Vec<u8>,
    },
}

/// Execute one link fuzz action.
async fn execute_next_action(
    input: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    next_transaction_id: &mut u64,
    endpoint_action_sender: &mesh::Sender<EndpointAction>,
) -> Result<(), anyhow::Error> {
    let action = input.arbitrary::<LinkAction>()?;
    fuzz_eprintln!("action: {action:?}");
    match action {
        LinkAction::LinkUp => {
            endpoint_action_sender.send(EndpointAction::LinkStatusNotify(true));
        }
        LinkAction::LinkDown => {
            endpoint_action_sender.send(EndpointAction::LinkStatusNotify(false));
        }
        LinkAction::RestartRequired => {
            endpoint_action_sender.send(EndpointAction::RestartRequired);
        }
        LinkAction::SendRndisPacket {
            ppi_bytes,
            frame_data,
        } => {
            let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
            send_rndis_via_direct_path(
                queue,
                mem,
                &rndis_buf,
                protocol::DATA_CHANNEL_TYPE,
                &LAYOUT,
                next_transaction_id,
            )
            .await?;
        }
    }
    Ok(())
}

fn do_fuzz(input: &[u8]) {
    let (endpoint, handles) = FuzzEndpoint::new(FuzzEndpointConfig {
        enable_rx_injection: false,
        enable_action_injection: true,
        ..FuzzEndpointConfig::default()
    });
    let action_send = handles.action_send.expect("action injection enabled");

    let config = FuzzNicConfig {
        endpoint: Box::new(endpoint),
        virtual_function: None,
        ..FuzzNicConfig::default()
    };

    run_fuzz_loop_with_config(input, &LAYOUT, config, |fuzzer_input, setup| {
        Box::pin(async move {
            let mut queue = setup.queue;
            let mem = setup.mem;
            let mut next_transaction_id = 1u64;

            negotiate_to_ready(
                &mut queue,
                &mut next_transaction_id,
                setup.recv_buf_gpadl_id,
                setup.send_buf_gpadl_id,
            )
            .await?;

            // Initialize RNDIS 90% of the time.
            if fuzzer_input.ratio(9, 10)? {
                rndis_initialize(
                    &mut queue,
                    &mem,
                    LAYOUT.data_page_start(),
                    LAYOUT.data_pages,
                    &mut next_transaction_id,
                )
                .await?;
            }

            // Run link-focused fuzz actions until input is exhausted.
            while !fuzzer_input.is_empty() {
                execute_next_action(
                    fuzzer_input,
                    &mut queue,
                    &mem,
                    &mut next_transaction_id,
                    &action_send,
                )
                .await?;
                drain_queue_async(&mut queue).await;
            }
            Ok(())
        })
    });
}

fuzz_target!(|input: &[u8]| do_fuzz(input));
