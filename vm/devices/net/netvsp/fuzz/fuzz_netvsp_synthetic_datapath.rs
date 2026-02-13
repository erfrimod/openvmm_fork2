// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for the NVSP synthetic data path (RNDIS packet messages).
//!
//! This fuzzer exercises the guest-to-host transmit path by sending arbitrary
//! RNDIS data packets through a VMBus channel to a connected NetVSP instance.
//! It performs a well-formed protocol negotiation first, then sends fuzzed
//! RNDIS packet messages via GpaDirect, including:
//!
//! - Malformed RNDIS headers (bad message_type, message_length)
//! - Malformed rndisprot::Packet fields (data_offset, data_length, PPI)
//! - Arbitrary per-packet info (PPI) chains (checksum, LSO, unknown types)
//! - Multiple concatenated RNDIS packets in one VMBus message
//! - Send buffer path with arbitrary section indices
//! - TX completion messages with arbitrary transaction IDs

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

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 4,
    data_pages: DATA_PAGES,
};

/// Actions the fuzzer can take on the data path.
#[derive(Arbitrary)]
enum DataPathAction {
    /// Send a single RNDIS packet message via GpaDirect with fuzzed content.
    SendRndisPacket {
        /// Structured RNDIS packet message.
        rndis: StructuredRndisPacketMessage,
        /// NVSP RNDIS packet metadata.
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a well-formed RNDIS packet with fuzzed PPI and data via GpaDirect.
    SendStructuredRndisPacket {
        /// Fuzzed per-packet-info bytes (PPI chain).
        ppi_bytes: Vec<u8>,
        /// Fuzzed ethernet frame data.
        frame_data: Vec<u8>,
        /// NVSP RNDIS packet metadata.
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send multiple concatenated RNDIS packets in one GpaDirect message.
    SendMultipleRndisPackets {
        /// Each entry is one structured RNDIS message.
        messages: Vec<StructuredRndisMessage>,
    },
    /// Send RNDIS data via the send buffer path (section index != 0xFFFFFFFF).
    SendViaSendBuffer {
        /// Structured RNDIS packet message to place in the send buffer.
        rndis: StructuredRndisPacketMessage,
        /// NVSP RNDIS packet metadata.
        nvsp_msg: protocol::Message1SendRndisPacket,
    },
    /// Send a TX completion with an arbitrary transaction ID (fuzz
    /// release_recv_buffers / completion handling).
    SendTxCompletion {
        transaction_id: u64,
        completion: protocol::Message1SendRndisPacketComplete,
    },
    /// Send an RNDIS control message (INITIALIZE, QUERY, SET, etc.).
    SendRndisControl {
        /// RNDIS message header.
        header: rndisprot::MessageHeader,
        /// Payload after the RNDIS MessageHeader.
        payload: Vec<u8>,
    },
    /// Drain completions from the host.
    ReadCompletion,
}

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

/// Execute one fuzz action on the data path.
async fn execute_action(
    u: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    let action = u.arbitrary::<DataPathAction>()?;
    match action {
        DataPathAction::SendRndisPacket {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);
            send_rndis_via_direct_path(queue, mem, &rndis_bytes, nvsp_msg.channel_type, tid)
                .await?;
        }
        DataPathAction::SendStructuredRndisPacket {
            ppi_bytes,
            frame_data,
            nvsp_msg,
        } => {
            // Build a structured RNDIS packet message with the fuzzed PPI and frame data.
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
        DataPathAction::SendMultipleRndisPackets { messages } => {
            // Concatenate multiple RNDIS packet messages into one GpaDirect.
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
        DataPathAction::SendViaSendBuffer {
            mut rndis,
            nvsp_msg,
        } => {
            let rndis_bytes = serialize_structured_rndis_packet_message(&mut rndis);

            // Write data into the send buffer GPADL area and reference it
            // via send_buffer_section_index.
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
        DataPathAction::SendTxCompletion {
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
        DataPathAction::SendRndisControl { header, payload } => {
            // Send an RNDIS control message with arbitrary message type
            // and payload via GpaDirect.
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
        DataPathAction::ReadCompletion => {
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

            // Always negotiate to the ready state first — data path messages are
            // only processed once the NIC is fully initialized.
            negotiate_to_ready(
                &mut queue,
                &mut tid,
                setup.recv_buf_gpadl_id,
                setup.send_buf_gpadl_id,
            )
            .await?;

            // 90% of the time, initialize RNDIS to reach Operational state.
            // The remaining 10% tests behavior when RNDIS packets arrive
            // before the initialize handshake.
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

            // Send arbitrary data path actions until the input is exhausted.
            while !u.is_empty() {
                execute_action(u, &mut queue, &mem, &mut tid).await?;
                drain_queue(&mut queue);
            }
            Ok(())
        })
    });
});
