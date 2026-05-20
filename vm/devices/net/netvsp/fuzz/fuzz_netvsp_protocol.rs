// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Combined protocol fuzzer for NVSP control, RNDIS OID, and TX path messages.
//!
//! This fuzzer exercises the full NVSP + RNDIS protocol state machine by
//! sending arbitrary sequences of control messages, OID queries/sets, and
//! data-path packets through a VMBus channel to a NetVSP instance. It
//! performs protocol negotiation first (with a fuzz-selected version pair),
//! optionally initializes RNDIS, then runs fuzz actions until input is
//! exhausted.
//!
//! After the main fuzz loop, a fuzz-selected teardown action is executed
//! (e.g. revoke buffer, RNDIS halt, fatal TX error injection) to exercise
//! cleanup paths.
//!
//! ## NVSP control messages tested
//!
//! - `MESSAGE_TYPE_INIT` — version negotiation (fuzz-selected pair from V2–V61)
//! - `MESSAGE2_TYPE_SEND_NDIS_CONFIG` — MTU and capabilities
//! - `MESSAGE1_TYPE_SEND_NDIS_VERSION` — NDIS version
//! - `MESSAGE1_TYPE_SEND_RECEIVE_BUFFER` / `MESSAGE1_TYPE_SEND_SEND_BUFFER`
//! - `MESSAGE4_TYPE_SWITCH_DATA_PATH` — data path switching
//! - `MESSAGE5_TYPE_SUB_CHANNEL` — subchannel allocation requests
//! - `MESSAGE5_TYPE_OID_QUERY_EX` — NVSP-level OID queries
//! - Arbitrary raw NVSP message types and payloads
//! - Arbitrary raw VMBus packet types
//!
//! ## RNDIS OID messages tested
//!
//! - `MESSAGE_TYPE_QUERY_MSG` — structured OID queries with arbitrary OID values
//! - `MESSAGE_TYPE_SET_MSG` — structured OID sets with arbitrary OID values
//! - Offload parameters, encapsulation, RSS, packet filter, config parameters
//! - Well-formed UTF-16LE config parameter names
//! - Structured offload parameters with clamped enum values
//!
//! ## TX path messages tested
//!
//! - RNDIS packet messages via GpaDirect with fuzzed PPI, LSO, and checksum
//! - Multiple concatenated RNDIS packets
//! - Send buffer path with arbitrary section indices
//! - TX completion messages with arbitrary transaction IDs
//! - TX error injection (TryRestart)
//!
//! ## RNDIS lifecycle messages tested
//!
//! - `MESSAGE_TYPE_INITIALIZE_MSG` — RNDIS initialize with fuzzed version
//! - `MESSAGE_TYPE_KEEPALIVE_MSG` — keepalive messages
//! - `MESSAGE_TYPE_RESET_MSG` — reset messages
//!
//! ## Teardown actions (executed after fuzz loop)
//!
//! - Revoke receive buffer / send buffer (terminates NIC worker)
//! - RNDIS halt
//! - Fatal TX error injection

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::DATA_PAGES;
use fuzz_helpers::KNOWN_CONFIG_PARAM_NAMES;
use fuzz_helpers::PageLayout;
use fuzz_helpers::SWITCH_DATA_PATH_TRANSACTION_ID;
use fuzz_helpers::StructuredPpiEntry;
use fuzz_helpers::StructuredRndisMessage;
use fuzz_helpers::StructuredRndisPacketMessage;
use fuzz_helpers::TeardownAction;
use fuzz_helpers::VF_ASSOCIATION_TRANSACTION_ID;
use fuzz_helpers::build_checksum_ppi_entry;
use fuzz_helpers::build_concatenated_rndis_messages;
use fuzz_helpers::build_lso_ppi_entry;
use fuzz_helpers::build_rndis_config_parameter;
use fuzz_helpers::build_rndis_message;
use fuzz_helpers::build_rndis_oid_query;
use fuzz_helpers::build_rndis_oid_set;
use fuzz_helpers::build_structured_rndis_packet;
use fuzz_helpers::drain_queue_async;
use fuzz_helpers::endpoint::FuzzEndpointConfig;
use fuzz_helpers::execute_teardown;
use fuzz_helpers::negotiate_to_ready_full;
use fuzz_helpers::nic_setup::FuzzNicConfig;
use fuzz_helpers::pick_version_pair;
use fuzz_helpers::rndis_initialize;
use fuzz_helpers::run_fuzz_loop_with_config;
use fuzz_helpers::send_completion_packet;
use fuzz_helpers::send_inband_nvsp;
use fuzz_helpers::send_rndis_control;
use fuzz_helpers::send_rndis_gpadirect;
use fuzz_helpers::send_rndis_via_direct_path;
use fuzz_helpers::send_rndis_via_send_buffer;
use fuzz_helpers::send_tx_rndis_completion;
use fuzz_helpers::serialize_ppi_chain;
use fuzz_helpers::serialize_structured_rndis_packet_message;
use fuzz_helpers::write_packet;
use guestmem::GuestMemory;
use netvsp::protocol;
use netvsp::rndisprot;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_ring::OutgoingPacketType;
use xtask_fuzz::fuzz_eprintln;
use xtask_fuzz::fuzz_target;
use zerocopy::IntoBytes;

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 4,
    data_pages: DATA_PAGES,
};

// ---- Fuzz actions ----

/// Actions the fuzzer can take after (optional) protocol negotiation.
/// This combines all NVSP control, RNDIS OID, and TX path actions into
/// a single enum to allow the fuzzer to interleave them freely.
#[derive(Arbitrary, Debug)]
enum ProtocolAction {
    // ==== Raw / low-level ====
    /// Send an arbitrary packet payload with a fuzzed packet type.
    SendRawPacket {
        #[arbitrary(with = fuzz_helpers::arbitrary_outgoing_packet_type)]
        packet_type: OutgoingPacketType<'static>,
        payload: Vec<u8>,
    },
    /// Send a raw NVSP message with arbitrary type and payload.
    SendRawInBand {
        message_type: u32,
        payload: Vec<u8>,
        with_completion: bool,
    },

    // ==== NVSP control ====
    /// Send a structured Init message with arbitrary version values.
    SendInit { init: protocol::MessageInit },
    /// Send an NDIS version message with arbitrary version numbers.
    SendNdisVersion {
        version: protocol::Message1SendNdisVersion,
    },
    /// Send NDIS config with arbitrary MTU and capabilities.
    SendNdisConfig {
        config: protocol::Message2SendNdisConfig,
    },
    /// Send a receive buffer message.
    SendReceiveBuffer {
        #[arbitrary(with = fuzz_helpers::arbitrary_send_receive_buffer_message)]
        msg: protocol::Message1SendReceiveBuffer,
    },
    /// Send a send buffer message.
    SendSendBuffer {
        #[arbitrary(with = fuzz_helpers::arbitrary_send_send_buffer_message)]
        msg: protocol::Message1SendSendBuffer,
    },
    /// Send a switch data path message.
    SwitchDataPath {
        msg: protocol::Message4SwitchDataPath,
    },
    /// Send a subchannel request.
    SubChannelRequest {
        request: protocol::Message5SubchannelRequest,
    },
    /// Send an OID query via the NVSP OidQueryEx message.
    OidQueryEx { msg: protocol::Message5OidQueryEx },
    /// Send a VF association completion (TID 0x8000000000000000).
    SendVfAssociationCompletion,
    /// Send a switch data path completion (TID 0x8000000000000001).
    SendSwitchDataPathCompletion,
    /// Send a completion packet with an arbitrary transaction ID and payload.
    SendRawCompletion { tid: u64, payload: Vec<u8> },

    // ==== RNDIS OID ====
    /// Send a structured OID query with a specific OID value.
    OidQuery {
        oid: rndisprot::Oid,
        extra_data: Vec<u8>,
    },
    /// Send an OID query with a fully fuzzed QueryRequest struct.
    OidQueryFull {
        request: rndisprot::QueryRequest,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set with a specific OID value and payload.
    OidSet {
        oid: rndisprot::Oid,
        payload: Vec<u8>,
    },
    /// Send an OID set with a fully fuzzed SetRequest struct.
    OidSetFull {
        request: rndisprot::SetRequest,
        payload: Vec<u8>,
    },
    /// Send a structured OID set for OID_TCP_OFFLOAD_PARAMETERS.
    SetOffloadParameters {
        params: rndisprot::NdisOffloadParameters,
    },
    /// Send a structured OID set for OID_OFFLOAD_ENCAPSULATION.
    SetOffloadEncapsulation {
        encap: rndisprot::NdisOffloadEncapsulation,
    },
    /// Send a structured OID set for OID_GEN_RNDIS_CONFIG_PARAMETER.
    SetRndisConfigParameter {
        info: rndisprot::RndisConfigParameterInfo,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_RECEIVE_SCALE_PARAMETERS.
    SetRssParameters {
        params: rndisprot::NdisReceiveScaleParameters,
        extra_data: Vec<u8>,
    },
    /// Send a structured OID set for OID_GEN_CURRENT_PACKET_FILTER.
    SetPacketFilter { filter: u32 },
    /// Send a well-formed `OID_GEN_RNDIS_CONFIG_PARAMETER` SET with a known
    /// parameter name (e.g. `*IPChecksumOffloadIPv4`) and a fuzz-selected
    /// `NdisParameterType`.
    SendKnownConfigParameter {
        name_idx: u8,
        param_type: rndisprot::NdisParameterType,
        value_bytes: Vec<u8>,
    },
    /// Set offload parameters with structured valid-range enum values so
    /// that `tx_rx()` and `enable()` are exercised across all match arms.
    SetStructuredOffloadParameters {
        ipv4_checksum: u8,
        tcp4_checksum: u8,
        udp4_checksum: u8,
        tcp6_checksum: u8,
        udp6_checksum: u8,
        lsov1: u8,
        lsov2_ipv4: u8,
        lsov2_ipv6: u8,
    },
    /// Set offload encapsulation with specific valid/invalid combinations.
    SetStructuredOffloadEncapsulation {
        ipv4_enabled: u32,
        ipv4_encap_type: u32,
        ipv4_header_size: u32,
        ipv6_enabled: u32,
        ipv6_encap_type: u32,
        ipv6_header_size: u32,
    },

    // ==== TX path ====
    /// Send a single RNDIS packet message via GpaDirect with fuzzed content.
    SendRndisPacket {
        rndis: StructuredRndisPacketMessage,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a structured RNDIS packet with fuzzed PPI and frame data via GpaDirect.
    SendStructuredRndisPacket {
        ppi_bytes: Vec<u8>,
        frame_data: Vec<u8>,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a structured RNDIS packet with a PPI chain containing properly
    /// formatted checksum and/or LSO entries.
    SendWithStructuredPpi {
        ppi_entries: Vec<StructuredPpiEntry>,
        frame_data: Vec<u8>,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a packet with a specific LSO PPI entry.
    SendLsoPacket {
        mss: u32,
        tcp_header_offset: u16,
        is_ipv6: bool,
        frame_data: Vec<u8>,
    },
    /// Send a packet with a specific checksum PPI entry.
    SendChecksumEdgeCase {
        checksum_info: u32,
        frame_data: Vec<u8>,
    },
    /// Send multiple concatenated RNDIS packets in one GpaDirect message.
    SendMultipleRndisPackets {
        messages: Vec<StructuredRndisMessage>,
    },
    /// Send RNDIS data via the send buffer path (section index != 0xFFFFFFFF).
    SendViaSendBuffer {
        rndis: StructuredRndisPacketMessage,
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a TX completion with an arbitrary transaction ID.
    SendTxCompletion {
        transaction_id: u64,
        completion: protocol::Message1SendRndisPacketComplete,
    },
    /// Send a raw MESSAGE1_TYPE_SEND_RNDIS_PACKET with adversarial
    /// send_buffer_section_index and send_buffer_section_size values.
    SendRawSendBufferPacket {
        send_buffer_section_index: u32,
        send_buffer_section_size: u32,
        channel_type: u32,
    },
    /// Inject a `TxError::TryRestart` on the next `tx_poll`, then send a
    /// packet to trigger `process_endpoint_tx`.
    InjectTxRestart {
        ppi_bytes: Vec<u8>,
        frame_data: Vec<u8>,
    },

    // ==== RNDIS control via GpaDirect ====
    /// Send an arbitrary RNDIS packet via GpaDirect on the data channel.
    SendRndisPacketDirect { payload: Vec<u8> },
    /// Send an arbitrary RNDIS control payload via GpaDirect on the control channel.
    SendRndisControlDirect { payload: Vec<u8> },
    /// Send an RNDIS control message with an arbitrary header and payload.
    SendRndisControl {
        header: rndisprot::MessageHeader,
        payload: Vec<u8>,
    },
    /// Send an RNDIS keepalive message.
    SendRndisKeepalive { request_id: u32 },
}

/// Execute one fuzz action.
async fn execute_next_action(
    input: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    next_transaction_id: &mut u64,
    tx_error_mode: &Option<Arc<AtomicU8>>,
) -> Result<(), anyhow::Error> {
    let action = input.arbitrary::<ProtocolAction>()?;
    fuzz_eprintln!("action: {action:?}");
    let tid = next_transaction_id;
    match action {
        // ==== Raw / low-level ====
        ProtocolAction::SendRawPacket {
            packet_type,
            payload,
        } => {
            write_packet(queue, tid, packet_type, &[&payload]).await?;
        }
        ProtocolAction::SendRawInBand {
            message_type,
            payload,
            with_completion,
        } => {
            // Remap worker-killing message types to 0 (unknown) so the
            // fuzzer doesn't accidentally terminate its own worker
            // mid-loop.  These teardown paths are exercised intentionally
            // via `TeardownAction`.
            let message_type = match message_type {
                protocol::MESSAGE1_TYPE_REVOKE_RECEIVE_BUFFER
                | protocol::MESSAGE1_TYPE_REVOKE_SEND_BUFFER => 0,
                other => other,
            };
            send_inband_nvsp(queue, tid, message_type, &payload, with_completion).await?;
        }

        // ==== NVSP control ====
        ProtocolAction::SendInit { init } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE_TYPE_INIT,
                init.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SendNdisVersion { version } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
                version.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SendNdisConfig { config } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
                config.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SendReceiveBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SendSendBuffer { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SwitchDataPath { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SubChannelRequest { request } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE5_TYPE_SUB_CHANNEL,
                request.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::OidQueryEx { msg } => {
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE5_TYPE_OID_QUERY_EX,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::SendVfAssociationCompletion => {
            send_completion_packet(queue, VF_ASSOCIATION_TRANSACTION_ID, &[]).await?;
        }
        ProtocolAction::SendSwitchDataPathCompletion => {
            send_completion_packet(queue, SWITCH_DATA_PATH_TRANSACTION_ID, &[]).await?;
        }
        ProtocolAction::SendRawCompletion {
            tid: raw_tid,
            payload,
        } => {
            send_completion_packet(queue, raw_tid, &[&payload]).await?;
        }

        // ==== RNDIS OID ====
        ProtocolAction::OidQuery { oid, extra_data } => {
            let rndis_bytes = build_rndis_oid_query(oid, &extra_data);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::OidQueryFull {
            request,
            extra_data,
        } => {
            let mut body = Vec::new();
            body.extend_from_slice(request.as_bytes());
            body.extend_from_slice(&extra_data);
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_QUERY_MSG, &body);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::OidSet { oid, payload } => {
            let rndis_bytes = build_rndis_oid_set(oid, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::OidSetFull { request, payload } => {
            let mut body = Vec::new();
            body.extend_from_slice(request.as_bytes());
            body.extend_from_slice(&payload);
            let rndis_bytes = build_rndis_message(rndisprot::MESSAGE_TYPE_SET_MSG, &body);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetOffloadParameters { params } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetOffloadEncapsulation { encap } => {
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION, encap.as_bytes());
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetRndisConfigParameter { info, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(info.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RNDIS_CONFIG_PARAMETER, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetRssParameters { params, extra_data } => {
            let mut payload = Vec::new();
            payload.extend_from_slice(params.as_bytes());
            payload.extend_from_slice(&extra_data);
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_GEN_RECEIVE_SCALE_PARAMETERS, &payload);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetPacketFilter { filter } => {
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_GEN_CURRENT_PACKET_FILTER,
                filter.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SendKnownConfigParameter {
            name_idx,
            param_type,
            value_bytes,
        } => {
            let names = KNOWN_CONFIG_PARAM_NAMES;
            let name = names[name_idx as usize % names.len()];
            let rndis_bytes = build_rndis_config_parameter(name, param_type, &value_bytes);
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetStructuredOffloadParameters {
            ipv4_checksum,
            tcp4_checksum,
            udp4_checksum,
            tcp6_checksum,
            udp6_checksum,
            lsov1,
            lsov2_ipv4,
            lsov2_ipv6,
        } => {
            let params = build_structured_offload_params(
                ipv4_checksum,
                tcp4_checksum,
                udp4_checksum,
                tcp6_checksum,
                udp6_checksum,
                lsov1,
                lsov2_ipv4,
                lsov2_ipv6,
            );
            let rndis_bytes = build_rndis_oid_set(
                rndisprot::Oid::OID_TCP_OFFLOAD_PARAMETERS,
                params.as_bytes(),
            );
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        ProtocolAction::SetStructuredOffloadEncapsulation {
            ipv4_enabled,
            ipv4_encap_type,
            ipv4_header_size,
            ipv6_enabled,
            ipv6_encap_type,
            ipv6_header_size,
        } => {
            let encap = rndisprot::NdisOffloadEncapsulation {
                header: rndisprot::NdisObjectHeader {
                    object_type: rndisprot::NdisObjectType::OFFLOAD_ENCAPSULATION,
                    revision: 1,
                    size: rndisprot::NDIS_SIZEOF_OFFLOAD_ENCAPSULATION_REVISION_1 as u16,
                },
                ipv4_enabled,
                ipv4_encapsulation_type: ipv4_encap_type,
                ipv4_header_size,
                ipv6_enabled,
                ipv6_encapsulation_type: ipv6_encap_type,
                ipv6_header_size,
            };
            let rndis_bytes =
                build_rndis_oid_set(rndisprot::Oid::OID_OFFLOAD_ENCAPSULATION, encap.as_bytes());
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
        // ==== TX path ====
        ProtocolAction::SendRndisPacket {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);
            send_rndis_via_direct_path(
                queue,
                mem,
                &rndis_bytes,
                nvsp_msg.channel_type,
                &LAYOUT,
                tid,
            )
            .await?;
        }
        ProtocolAction::SendStructuredRndisPacket {
            ppi_bytes,
            frame_data,
            nvsp_msg,
        } => {
            let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
            send_rndis_via_direct_path(queue, mem, &rndis_buf, nvsp_msg.channel_type, &LAYOUT, tid)
                .await?;
        }
        ProtocolAction::SendWithStructuredPpi {
            ppi_entries,
            frame_data,
            nvsp_msg,
        } => {
            let ppi_bytes = serialize_ppi_chain(&ppi_entries);
            let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
            send_rndis_via_direct_path(queue, mem, &rndis_buf, nvsp_msg.channel_type, &LAYOUT, tid)
                .await?;
        }
        ProtocolAction::SendLsoPacket {
            mss,
            tcp_header_offset,
            is_ipv6,
            frame_data,
        } => {
            let ppi_bytes = build_lso_ppi_entry(mss, tcp_header_offset, is_ipv6);
            let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
            send_rndis_via_direct_path(
                queue,
                mem,
                &rndis_buf,
                protocol::DATA_CHANNEL_TYPE,
                &LAYOUT,
                tid,
            )
            .await?;
        }
        ProtocolAction::SendChecksumEdgeCase {
            checksum_info,
            frame_data,
        } => {
            let ppi_bytes = build_checksum_ppi_entry(checksum_info);
            let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
            send_rndis_via_direct_path(
                queue,
                mem,
                &rndis_buf,
                protocol::DATA_CHANNEL_TYPE,
                &LAYOUT,
                tid,
            )
            .await?;
        }
        ProtocolAction::SendMultipleRndisPackets { messages } => {
            let rndis_buf = build_concatenated_rndis_messages(&messages);
            if !rndis_buf.is_empty() {
                send_rndis_via_direct_path(
                    queue,
                    mem,
                    &rndis_buf,
                    protocol::DATA_CHANNEL_TYPE,
                    &LAYOUT,
                    tid,
                )
                .await?;
            }
        }
        ProtocolAction::SendViaSendBuffer {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);
            send_rndis_via_send_buffer(queue, mem, &rndis_bytes, &nvsp_msg, &LAYOUT, tid).await?;
        }
        ProtocolAction::SendTxCompletion {
            transaction_id,
            completion,
        } => {
            send_tx_rndis_completion(queue, transaction_id, &completion).await?;
        }
        ProtocolAction::SendRawSendBufferPacket {
            send_buffer_section_index,
            send_buffer_section_size,
            channel_type,
        } => {
            let msg = protocol::Message1SendRndisPacket {
                channel_type,
                send_buffer_section_index,
                send_buffer_section_size,
            };
            send_inband_nvsp(
                queue,
                tid,
                protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        ProtocolAction::InjectTxRestart {
            ppi_bytes,
            frame_data,
        } => {
            if let Some(mode) = tx_error_mode {
                mode.store(1, Ordering::Relaxed);
                let rndis_buf = build_structured_rndis_packet(&ppi_bytes, &frame_data);
                let _ = send_rndis_via_direct_path(
                    queue,
                    mem,
                    &rndis_buf,
                    protocol::DATA_CHANNEL_TYPE,
                    &LAYOUT,
                    tid,
                )
                .await;
                fuzz_helpers::yield_to_executor(20).await;
                drain_queue_async(queue).await;
            }
        }

        // ==== RNDIS control via GpaDirect ====
        ProtocolAction::SendRndisPacketDirect { payload } => {
            send_rndis_via_direct_path(
                queue,
                mem,
                &payload,
                protocol::DATA_CHANNEL_TYPE,
                &LAYOUT,
                tid,
            )
            .await?;
        }
        ProtocolAction::SendRndisControlDirect { payload } => {
            send_rndis_via_direct_path(
                queue,
                mem,
                &payload,
                protocol::CONTROL_CHANNEL_TYPE,
                &LAYOUT,
                tid,
            )
            .await?;
        }
        ProtocolAction::SendRndisControl { header, payload } => {
            // Remap worker-killing RNDIS message types to KEEPALIVE so the
            // fuzzer doesn't accidentally terminate its own worker mid-loop.
            // RESET is exercised via `TeardownAction::SendRndisReset`.
            let message_type = match header.message_type {
                rndisprot::MESSAGE_TYPE_RESET_MSG | rndisprot::MESSAGE_TYPE_HALT_MSG => {
                    rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG
                }
                other => other,
            };
            let rndis_buf = build_rndis_message(message_type, &payload);
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
        ProtocolAction::SendRndisKeepalive { request_id } => {
            let keepalive = rndisprot::KeepaliveRequest { request_id };
            let rndis_bytes =
                build_rndis_message(rndisprot::MESSAGE_TYPE_KEEPALIVE_MSG, keepalive.as_bytes());
            send_rndis_control(queue, mem, &rndis_bytes, &LAYOUT, tid).await?;
        }
    }
    Ok(())
}

/// Build `NdisOffloadParameters` with each field clamped to its valid
/// discriminant range so that `tx_rx()` and `enable()` are exercised
/// across all their match arms rather than falling through to `None`.
fn build_structured_offload_params(
    ipv4_checksum: u8,
    tcp4_checksum: u8,
    udp4_checksum: u8,
    tcp6_checksum: u8,
    udp6_checksum: u8,
    lsov1: u8,
    lsov2_ipv4: u8,
    lsov2_ipv6: u8,
) -> rndisprot::NdisOffloadParameters {
    rndisprot::NdisOffloadParameters {
        header: rndisprot::NdisObjectHeader {
            object_type: rndisprot::NdisObjectType::DEFAULT,
            revision: 1,
            size: rndisprot::NDIS_SIZEOF_OFFLOAD_PARAMETERS_REVISION_1 as u16,
        },
        ipv4_checksum: rndisprot::OffloadParametersChecksum(ipv4_checksum % 5),
        tcp4_checksum: rndisprot::OffloadParametersChecksum(tcp4_checksum % 5),
        udp4_checksum: rndisprot::OffloadParametersChecksum(udp4_checksum % 5),
        tcp6_checksum: rndisprot::OffloadParametersChecksum(tcp6_checksum % 5),
        udp6_checksum: rndisprot::OffloadParametersChecksum(udp6_checksum % 5),
        lsov1: rndisprot::OffloadParametersSimple(lsov1 % 3),
        ipsec_v1: 0,
        lsov2_ipv4: rndisprot::OffloadParametersSimple(lsov2_ipv4 % 3),
        lsov2_ipv6: rndisprot::OffloadParametersSimple(lsov2_ipv6 % 3),
        tcp_connection_ipv4: 0,
        tcp_connection_ipv6: 0,
        reserved: 0,
        flags: 0,
    }
}

fn do_fuzz(input: &[u8]) {
    let (endpoint, handles) = fuzz_helpers::endpoint::FuzzEndpoint::new(FuzzEndpointConfig {
        enable_tx_error_injection: true,
        enable_async_tx: true,
        ..FuzzEndpointConfig::default()
    });
    let tx_error_mode = handles.tx_error_mode;

    run_fuzz_loop_with_config(
        input,
        &LAYOUT,
        FuzzNicConfig {
            endpoint: Box::new(endpoint),
            ..FuzzNicConfig::default()
        },
        |fuzzer_input, setup| {
            Box::pin(async move {
                let mut queue = setup.queue;
                let mem = setup.mem;
                let mut next_transaction_id = 1u64;

                // Pick a fuzz-selected teardown action up front.
                let teardown = fuzzer_input
                    .arbitrary::<TeardownAction>()
                    .unwrap_or(TeardownAction::None);

                // Pick a fuzzer-driven protocol version pair.
                let version_init = pick_version_pair(fuzzer_input)?;

                negotiate_to_ready_full(
                    &mut queue,
                    &mut next_transaction_id,
                    setup.recv_buf_gpadl_id,
                    setup.send_buf_gpadl_id,
                    protocol::NdisConfigCapabilities::new(),
                    version_init,
                )
                .await?;

                // 90% of the time, initialize RNDIS to reach Operational state.
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

                // Run fuzz actions until input is exhausted.
                while !fuzzer_input.is_empty() {
                    execute_next_action(
                        fuzzer_input,
                        &mut queue,
                        &mem,
                        &mut next_transaction_id,
                        &tx_error_mode,
                    )
                    .await?;
                    drain_queue_async(&mut queue).await;
                }

                // Execute the teardown action chosen at the start.
                let _ = execute_teardown(
                    teardown,
                    &mut queue,
                    &mem,
                    &LAYOUT,
                    &mut next_transaction_id,
                    &tx_error_mode,
                )
                .await;

                Ok(())
            })
        },
    );
}

fuzz_target!(|input: &[u8]| do_fuzz(input));
