// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for RNDIS OID query and OID set operations in NetVSP.
//!
//! This fuzzer exercises the `handle_oid_query` and `handle_oid_set` code
//! paths by sending arbitrary RNDIS QUERY_MSG and SET_MSG control messages
//! through a VMBus channel to a fully-initialized NetVSP instance.
//!
//! It first performs NVSP protocol negotiation and RNDIS initialization to
//! reach the operational state where OID messages are processed, then sends
//! structured and unstructured OID query/set messages with fuzzed OID values,
//! payloads, and offsets.

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

#[path = "fuzz_helpers.rs"]
#[allow(dead_code)]
mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::DATA_PAGES;
use fuzz_helpers::PageLayout;
use fuzz_helpers::build_rndis_message;
use fuzz_helpers::build_rndis_oid_query;
use fuzz_helpers::build_rndis_oid_set;
use fuzz_helpers::drain_queue;
use fuzz_helpers::negotiate_to_ready;
use fuzz_helpers::rndis_initialize;
use fuzz_helpers::run_fuzz_loop;
use fuzz_helpers::send_rndis_gpadirect;
use fuzz_helpers::try_read_one_completion;
use guestmem::GuestMemory;
use netvsp::protocol;
use netvsp::rndisprot;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use xtask_fuzz::fuzz_target;
use zerocopy::IntoBytes;

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 1,
    data_pages: DATA_PAGES,
};

/// Actions the fuzzer can take to exercise OID query/set handling.
#[derive(Arbitrary)]
enum OidFuzzAction {
    /// Send a structured OID query with a specific OID value.
    OidQuery {
        /// The OID to query.
        oid: rndisprot::Oid,
        /// Extra data to append after the QueryRequest struct.
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set with a specific OID value and payload.
    OidSet {
        /// The OID to set.
        oid: rndisprot::Oid,
        /// The information buffer payload for the OID set.
        payload: Vec<u8>,
    },
    /// Send a fully raw RNDIS QUERY_MSG with arbitrary bytes.
    RawOidQuery {
        /// Raw bytes after the RNDIS MessageHeader.
        raw_payload: Vec<u8>,
    },
    /// Send a fully raw RNDIS SET_MSG with arbitrary bytes.
    RawOidSet {
        /// Raw bytes after the RNDIS MessageHeader.
        raw_payload: Vec<u8>,
    },
    /// Send a structured OID set for OID_TCP_OFFLOAD_PARAMETERS.
    SetOffloadParameters {
        /// Fuzzed offload parameters (includes NdisObjectHeader).
        params: rndisprot::NdisOffloadParameters,
    },
    /// Send a structured OID set for OID_OFFLOAD_ENCAPSULATION.
    SetOffloadEncapsulation {
        /// Fuzzed encapsulation settings (includes NdisObjectHeader).
        encap: rndisprot::NdisOffloadEncapsulation,
    },
    /// Send a structured OID set for OID_GEN_RNDIS_CONFIG_PARAMETER.
    SetRndisConfigParameter {
        /// Fuzzed config parameter info header.
        info: rndisprot::RndisConfigParameterInfo,
        /// Extra data appended after the info struct (name + value data).
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_RECEIVE_SCALE_PARAMETERS.
    SetRssParameters {
        /// Fuzzed RSS parameters (includes NdisObjectHeader).
        params: rndisprot::NdisReceiveScaleParameters,
        /// Extra trailing data (hash key, indirection table).
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_CURRENT_PACKET_FILTER.
    SetPacketFilter {
        /// The packet filter value.
        filter: u32,
    },
    /// Drain completions from the host.
    ReadCompletion,
}

/// Helper to send an RNDIS control message via GpaDirect.
async fn send_rndis_control(
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    rndis_bytes: &[u8],
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    send_rndis_gpadirect(
        queue,
        mem,
        rndis_bytes,
        protocol::CONTROL_CHANNEL_TYPE,
        LAYOUT.data_page_start(),
        LAYOUT.data_pages,
        tid,
    )
    .await
}

/// Execute one OID fuzz action.
async fn execute_action(
    u: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    let action = u.arbitrary::<OidFuzzAction>()?;
    match action {
        OidFuzzAction::OidQuery { oid, extra_data } => {
            let rndis_bytes = build_rndis_oid_query(oid, &extra_data);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::OidSet { oid, payload } => {
            let rndis_bytes = build_rndis_oid_set(oid, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::RawOidQuery { raw_payload } => {
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_QUERY_MSG, &raw_payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::RawOidSet { raw_payload } => {
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_SET_MSG, &raw_payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::SetOffloadParameters { params } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::SetOffloadEncapsulation { encap } => {
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION, encap.as_bytes());
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::SetRndisConfigParameter { info, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(info.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::SetRssParameters { params, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(params.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::SetPacketFilter { filter } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER,
                filter.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        OidFuzzAction::ReadCompletion => {
            let _ = try_read_one_completion(queue);
        }
    }
    Ok(())
}

fuzz_target!(|input: &[u8]| {
    run_fuzz_loop(input, &LAYOUT, |u, setup| {
        Box::pin(async move {
            let mut queue = setup.queue;
            let mem = setup.mem;
            let mut tid = 1u64;

            // Negotiate NVSP protocol to the ready state.
            negotiate_to_ready(
                &mut queue,
                &mut tid,
                setup.recv_buf_gpadl_id,
                setup.send_buf_gpadl_id,
            )
            .await?;

            // 90% of the time, initialize RNDIS to reach Operational state.
            // The remaining 10% tests OID handling before the initialize handshake.
            if u.ratio(9, 10)? {
                rndis_initialize(
                    &mut queue,
                    &mem,
                    LAYOUT.data_page_start(),
                    LAYOUT.data_pages,
                    &mut tid,
                )
                .await?;
            }

            // Send arbitrary OID fuzz actions until input is exhausted.
            while !u.is_empty() {
                execute_action(u, &mut queue, &mem, &mut tid).await?;
                drain_queue(&mut queue);
            }
            Ok(())
        })
    });
});
