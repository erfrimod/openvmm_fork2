// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interop fuzzer that combines OID, control, and synthetic datapath actions.
//!
//! This fuzzer exercises cross-domain interactions by interleaving arbitrary
//! sequences of NVSP control messages, RNDIS OID operations, and RNDIS data
//! path packets in a single session. This finds bugs that only manifest when
//! different subsystems interact — for example, sending data packets while OID
//! sets are in flight, or issuing control messages mid-transfer.
//!
//! The fuzzer optionally performs a well-formed NVSP/RNDIS negotiation before
//! sending arbitrary interleaved actions from all three domains.

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

#[path = "fuzz_helpers.rs"]
#[allow(dead_code)]
mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::DATA_PAGES;
use fuzz_helpers::PageLayout;
use fuzz_helpers::RECV_BUF_PAGES;
use fuzz_helpers::RING_PAGES;
use fuzz_helpers::SEND_BUFFER_SECTION_SIZE_BYTES;
use fuzz_helpers::StructuredRndisMessage;
use fuzz_helpers::StructuredRndisPacketMessage;
use fuzz_helpers::build_rndis_message;
use fuzz_helpers::build_rndis_oid_query;
use fuzz_helpers::build_rndis_oid_set;
use fuzz_helpers::drain_queue;
use fuzz_helpers::negotiate_to_ready;
use fuzz_helpers::nvsp_payload;
use fuzz_helpers::nvsp_rndis_payload;
use fuzz_helpers::rndis_initialize;
use fuzz_helpers::run_fuzz_loop;
use fuzz_helpers::send_gpadirect;
use fuzz_helpers::send_inband_nvsp;
use fuzz_helpers::send_rndis_gpadirect;
use fuzz_helpers::serialize_structured_rndis_packet_message;
use fuzz_helpers::try_read_one_completion;
use fuzz_helpers::write_packet;
use fuzz_helpers::write_to_guest;
use guestmem::GuestMemory;
use netvsp::protocol;
use netvsp::rndisprot;
use vmbus_async::queue::OutgoingPacket;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_ring::OutgoingPacketType;
use vmbus_ring::PAGE_SIZE;
use xtask_fuzz::fuzz_target;
use zerocopy::IntoBytes;

/// Use the most demanding layout: send buffer for the send-buffer path,
/// data pages for GpaDirect RNDIS messages.
const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 4,
    data_pages: DATA_PAGES,
};

// ---- Combined interop actions ----

/// Actions spanning all three fuzzing domains: control, OID, and data path.
#[derive(Arbitrary)]
enum InteropAction {
    // ==== NVSP Control actions ====
    /// Send an arbitrary packet payload with a fuzzed packet type.
    ControlSendRawPacket {
        #[arbitrary(with = fuzz_helpers::arbitrary_outgoing_packet_type)]
        packet_type: OutgoingPacketType<'static>,
        payload: Vec<u8>,
    },
    /// Send a raw NVSP message with arbitrary type and payload.
    ControlSendRawInBand {
        message_type: u32,
        payload: Vec<u8>,
        with_completion: bool,
    },
    /// Send a well-formed Init message with arbitrary version.
    ControlSendInit { init: protocol::MessageInit },
    /// Send an NDIS version message with arbitrary version numbers.
    ControlSendNdisVersion {
        version: protocol::Message1SendNdisVersion,
    },
    /// Send NDIS config with arbitrary MTU and capabilities.
    ControlSendNdisConfig {
        config: protocol::Message2SendNdisConfig,
    },
    /// Send a receive buffer message.
    ControlSendReceiveBuffer {
        #[arbitrary(with = fuzz_helpers::arbitrary_send_receive_buffer_message)]
        msg: protocol::Message1SendReceiveBuffer,
    },
    /// Send a send buffer message.
    ControlSendSendBuffer {
        #[arbitrary(with = fuzz_helpers::arbitrary_send_send_buffer_message)]
        msg: protocol::Message1SendSendBuffer,
    },
    /// Send a revoke receive buffer message.
    ControlRevokeReceiveBuffer {
        msg: protocol::Message1RevokeReceiveBuffer,
    },
    /// Send a revoke send buffer message.
    ControlRevokeSendBuffer {
        msg: protocol::Message1RevokeSendBuffer,
    },
    /// Send a switch data path message.
    ControlSwitchDataPath {
        msg: protocol::Message4SwitchDataPath,
    },
    /// Send a subchannel request.
    ControlSubChannelRequest {
        request: protocol::Message5SubchannelRequest,
    },
    /// Send an OID query via the NVSP OidQueryEx message.
    ControlOidQueryEx { msg: protocol::Message5OidQueryEx },

    // ==== RNDIS OID actions ====
    /// Send a structured OID query with a specific OID value.
    OidQuery {
        oid: rndisprot::Oid,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set with a specific OID value and payload.
    OidSet {
        oid: rndisprot::Oid,
        payload: Vec<u8>,
    },
    /// Send a fully raw RNDIS QUERY_MSG with arbitrary bytes.
    RawOidQuery { raw_payload: Vec<u8> },
    /// Send a fully raw RNDIS SET_MSG with arbitrary bytes.
    RawOidSet { raw_payload: Vec<u8> },
    /// Send a structured OID set for OID_TCP_OFFLOAD_PARAMETERS.
    OidSetOffloadParameters {
        params: rndisprot::NdisOffloadParameters,
    },
    /// Send a structured OID set for OID_OFFLOAD_ENCAPSULATION.
    OidSetOffloadEncapsulation {
        encap: rndisprot::NdisOffloadEncapsulation,
    },
    /// Send a structured OID set for OID_GEN_RNDIS_CONFIG_PARAMETER.
    OidSetRndisConfigParameter {
        info: rndisprot::RndisConfigParameterInfo,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_RECEIVE_SCALE_PARAMETERS.
    OidSetRssParameters {
        params: rndisprot::NdisReceiveScaleParameters,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_CURRENT_PACKET_FILTER.
    OidSetPacketFilter { filter: u32 },

    // ==== Synthetic data path actions ====
    /// Send a single RNDIS packet message via GpaDirect with fuzzed content.
    DataSendRndisPacket {
        rndis: StructuredRndisPacketMessage,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a well-formed RNDIS packet with fuzzed PPI and data via GpaDirect.
    DataSendStructuredRndisPacket {
        ppi_bytes: Vec<u8>,
        frame_data: Vec<u8>,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send multiple concatenated RNDIS packets in one GpaDirect message.
    DataSendMultipleRndisPackets {
        messages: Vec<StructuredRndisMessage>,
    },
    /// Send RNDIS data via the send buffer path.
    DataSendViaSendBuffer {
        rndis: StructuredRndisPacketMessage,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a TX completion with an arbitrary transaction ID.
    DataSendTxCompletion {
        transaction_id: u64,
        completion: protocol::Message1SendRndisPacketComplete,
    },
    /// Send an RNDIS control message (INITIALIZE, QUERY, SET, etc.) via the
    /// data path GpaDirect path.
    DataSendRndisControl {
        header: rndisprot::MessageHeader,
        payload: Vec<u8>,
    },

    // ==== Common actions ====
    /// Drain completions from the host.
    ReadCompletion,
}

// ---- Send helpers ----

/// Send an RNDIS control message via GpaDirect on the control channel.
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

/// Send RNDIS data via GpaDirect with NVSP wrapping.
async fn send_rndis_via_direct_path(
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    rndis_bytes: &[u8],
    channel_type: u32,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    if let Some(byte_len) = write_to_guest(
        mem,
        rndis_bytes,
        LAYOUT.data_page_start(),
        LAYOUT.data_pages,
    ) {
        let nvsp = nvsp_rndis_payload(channel_type, 0xffffffff, 0);
        send_gpadirect(queue, LAYOUT.data_page_start(), byte_len, &nvsp, tid).await?;
    }
    Ok(())
}

// ---- Action execution ----

/// Execute one interop fuzz action.
async fn execute_action(
    u: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    let action = u.arbitrary::<InteropAction>()?;
    match action {
        // ==== NVSP Control ====
        InteropAction::ControlSendRawPacket {
            packet_type,
            payload,
        } => {
            write_packet(queue, tid, packet_type, &[&payload]).await?;
        }
        InteropAction::ControlSendRawInBand {
            message_type,
            payload,
            with_completion,
        } => {
            send_inband_nvsp(queue, tid, message_type, &payload, with_completion).await?;
        }
        InteropAction::ControlSendInit { init } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE_TYPE_INIT,
                init.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSendNdisVersion { version } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
                version.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSendNdisConfig { config } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
                config.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSendReceiveBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSendSendBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlRevokeReceiveBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_REVOKE_RECEIVE_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlRevokeSendBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_REVOKE_SEND_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSwitchDataPath { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlSubChannelRequest { request } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE5_TYPE_SUB_CHANNEL,
                request.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::ControlOidQueryEx { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE5_TYPE_OID_QUERY_EX,
                msg.as_bytes(),
                true,
            )
            .await?;
        }

        // ==== RNDIS OID ====
        InteropAction::OidQuery { oid, extra_data } => {
            let rndis_bytes = build_rndis_oid_query(oid, &extra_data);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSet { oid, payload } => {
            let rndis_bytes = build_rndis_oid_set(oid, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::RawOidQuery { raw_payload } => {
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_QUERY_MSG, &raw_payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::RawOidSet { raw_payload } => {
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_SET_MSG, &raw_payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSetOffloadParameters { params } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSetOffloadEncapsulation { encap } => {
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION, encap.as_bytes());
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSetRndisConfigParameter { info, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(info.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSetRssParameters { params, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(params.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }
        InteropAction::OidSetPacketFilter { filter } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER,
                filter.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, tid).await?;
        }

        // ==== Synthetic data path ====
        InteropAction::DataSendRndisPacket {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);
            send_rndis_via_direct_path(queue, mem, &rndis_bytes, nvsp_msg.channel_type, tid)
                .await?;
        }
        InteropAction::DataSendStructuredRndisPacket {
            ppi_bytes,
            frame_data,
            nvsp_msg,
        } => {
            let ppi_len = ppi_bytes.len();
            let data_offset = (size_of::<rndisprot::Packet>() + ppi_len) as u32;
            let data_len = frame_data.len() as u32;
            let total_rndis_len = size_of::<rndisprot::MessageHeader>()
                + size_of::<rndisprot::Packet>()
                + ppi_len
                + frame_data.len();

            let rndis_header = rndisprot::MessageHeader {
                message_type: rndisprot::MESSAGE_TYPE_PACKET_MSG,
                message_length: total_rndis_len as u32,
            };
            let rndis_packet = rndisprot::Packet {
                data_offset,
                data_length: data_len,
                oob_data_offset: 0,
                oob_data_length: 0,
                num_oob_data_elements: 0,
                per_packet_info_offset: if ppi_len > 0 {
                    size_of::<rndisprot::Packet>() as u32
                } else {
                    0
                },
                per_packet_info_length: ppi_len as u32,
                vc_handle: 0,
                reserved: 0,
            };

            let mut rndis_buf = Vec::with_capacity(total_rndis_len);
            rndis_buf.extend_from_slice(rndis_header.as_bytes());
            rndis_buf.extend_from_slice(rndis_packet.as_bytes());
            rndis_buf.extend_from_slice(&ppi_bytes);
            rndis_buf.extend_from_slice(&frame_data);
            send_rndis_via_direct_path(queue, mem, &rndis_buf, nvsp_msg.channel_type, tid).await?;
        }
        InteropAction::DataSendMultipleRndisPackets { messages } => {
            let mut rndis_buf = Vec::new();
            for message in &messages {
                let mut header = message.header;
                header.message_length =
                    (size_of::<rndisprot::MessageHeader>() + message.payload.len()) as u32;
                rndis_buf.extend_from_slice(header.as_bytes());
                rndis_buf.extend_from_slice(&message.payload);
            }

            if !rndis_buf.is_empty() {
                send_rndis_via_direct_path(
                    queue,
                    mem,
                    &rndis_buf,
                    protocol::DATA_CHANNEL_TYPE,
                    tid,
                )
                .await?;
            }
        }
        InteropAction::DataSendViaSendBuffer {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);

            let send_buf_page_start = RING_PAGES + RECV_BUF_PAGES;
            let send_buf_max = LAYOUT.send_buf_pages * PAGE_SIZE;
            let write_len = rndis_bytes.len().min(send_buf_max);
            if write_len > 0 {
                let base_addr = (send_buf_page_start * PAGE_SIZE) as u64;
                let offset = (nvsp_msg.send_buffer_section_index as usize)
                    .wrapping_mul(SEND_BUFFER_SECTION_SIZE_BYTES)
                    % send_buf_max;
                let _ = mem.write_at(base_addr + offset as u64, &rndis_bytes[..write_len]);
            }

            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET,
                nvsp_msg.as_bytes(),
                true,
            )
            .await?;
        }
        InteropAction::DataSendTxCompletion {
            transaction_id,
            completion,
        } => {
            let payload = nvsp_payload(
                protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET_COMPLETE,
                completion.as_bytes(),
            );
            let (_, mut writer) = queue.split();
            writer
                .write(OutgoingPacket {
                    transaction_id,
                    packet_type: OutgoingPacketType::InBandWithCompletion,
                    payload: &[&payload],
                })
                .await?;
        }
        InteropAction::DataSendRndisControl { header, payload } => {
            let rndis_buf = build_rndis_message(header.message_type, &payload);
            send_rndis_gpadirect(
                queue,
                mem,
                &rndis_buf,
                protocol::CONTROL_CHANNEL_TYPE,
                LAYOUT.data_page_start(),
                LAYOUT.data_pages,
                tid,
            )
            .await?;
        }

        // ==== Common ====
        InteropAction::ReadCompletion => {
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

            // 90% of the time, negotiate NVSP protocol to the ready state.
            // The remaining 10% tests behavior with no negotiation at all,
            // exercising interleaved actions against an uninitialized NIC.
            if u.ratio(9, 10)? {
                negotiate_to_ready(
                    &mut queue,
                    &mut tid,
                    setup.recv_buf_gpadl_id,
                    setup.send_buf_gpadl_id,
                )
                .await?;

                // 90% of those times, also initialize RNDIS to reach
                // Operational state. The remaining 10% tests interactions
                // before RNDIS initialization.
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
            }

            // Send arbitrary interleaved actions until input is exhausted.
            while !u.is_empty() {
                execute_action(u, &mut queue, &mem, &mut tid).await?;
                drain_queue(&mut queue);
            }
            Ok(())
        })
    });
});
