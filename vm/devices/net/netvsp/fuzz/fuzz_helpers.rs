// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for netvsp fuzz targets.
//!
//! Provides common infrastructure for setting up a NIC on a mock VMBus,
//! registering GPADLs, opening channels, building NVSP/RNDIS payloads,
//! performing protocol negotiation, and running the fuzz loop boilerplate.
//!
//! # Module organization
//!
//! - **Page layout**: [`PageLayout`], [`RING_PAGES`], [`RECV_BUF_PAGES`],
//!   [`DATA_PAGES`]
//! - **Low-level VMBus I/O**: [`write_packet`]
//! - **NVSP message building**: [`nvsp_payload`], [`nvsp_rndis_payload`],
//!   [`send_inband_nvsp`]
//! - **NVSP protocol negotiation**: [`negotiate_to_ready`]
//! - **RNDIS helpers**: [`build_rndis_message`], [`build_rndis_oid_query`],
//!   [`build_rndis_oid_set`], [`rndis_initialize`], [`write_to_guest`],
//!   [`send_gpadirect`], [`send_rndis_gpadirect`]
//! - **Shared fuzz types**: [`StructuredRndisMessage`],
//!   [`StructuredRndisPacketMessage`],
//!   [`serialize_structured_rndis_packet_message`],
//!   [`SEND_BUFFER_SECTION_SIZE_BYTES`]
//! - **Arbitrary generators**: [`arbitrary_outgoing_packet_type`],
//!   [`arbitrary_send_receive_buffer_message`],
//!   [`arbitrary_send_send_buffer_message`]
//! - **NIC setup**: [`setup_fuzz_nic`]
//! - **Fuzz loop boilerplate**: [`FuzzNicSetup`],
//!   [`try_read_one_completion`], [`drain_queue`], [`run_fuzz_loop`]

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use guestmem::GuestMemory;
use guestmem::MemoryRead;
use guestmem::ranges::PagedRange;
use guid::Guid;
use mesh::rpc::RpcSend;
use net_backend::null::NullEndpoint;
use netvsp::Nic;
use netvsp::protocol;
use netvsp::rndisprot;
use netvsp::test_helpers::CapturingMockVmbus;
use netvsp::test_helpers::gpadl_test_guest_channel;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use vmbus_async::queue::IncomingPacket;
use vmbus_async::queue::OutgoingPacket;
use vmbus_async::queue::Queue;
use vmbus_channel::bus::ChannelRequest;
use vmbus_channel::bus::GpadlRequest;
use vmbus_channel::bus::OpenData;
use vmbus_channel::bus::OpenRequest;
use vmbus_channel::channel::offer_channel;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMap;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_core::protocol::UserDefinedData;
use vmbus_ring::OutgoingPacketType;
use vmbus_ring::PAGE_SIZE;
use vmbus_ring::gparange::MultiPagedRangeBuf;
use vmcore::interrupt::Interrupt;
use vmcore::slim_event::SlimEvent;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use zerocopy::FromZeros;
use zerocopy::IntoBytes;

// ===========================================================================
// Page layout
// ===========================================================================

/// Number of pages used for the VMBus ring buffer.
pub const RING_PAGES: usize = 4;
/// Number of pages used for the receive buffer GPADL.
pub const RECV_BUF_PAGES: usize = 9;
/// Number of extra pages for writing fuzzed RNDIS data via GpaDirect.
pub const DATA_PAGES: usize = 4;

/// Describes the guest memory page layout for a fuzz target.
///
/// The layout is: ring pages | receive buffer | send buffer | data pages.
/// `data_pages` may be zero for fuzz targets that don't send GpaDirect data.
pub struct PageLayout {
    /// Number of pages for the send buffer GPADL.
    pub send_buf_pages: usize,
    /// Number of extra pages for fuzzed RNDIS data (0 if unused).
    pub data_pages: usize,
}

impl PageLayout {
    /// Total guest memory pages needed.
    pub const fn total_pages(&self) -> usize {
        RING_PAGES + RECV_BUF_PAGES + self.send_buf_pages + self.data_pages
    }

    /// Page offset where fuzzed RNDIS data starts (after ring + recv + send).
    pub const fn data_page_start(&self) -> usize {
        RING_PAGES + RECV_BUF_PAGES + self.send_buf_pages
    }
}

// ===========================================================================
// Low-level VMBus I/O
// ===========================================================================

/// GPADL allocation configuration for a single buffer region.
struct GpadlAlloc {
    gpadl_id: GpadlId,
    pages: Vec<u64>,
}

/// Write one outgoing packet and increment transaction ID.
pub async fn write_packet(
    queue: &mut Queue<GpadlRingMem>,
    tid: &mut u64,
    packet_type: OutgoingPacketType<'_>,
    payload: &[&[u8]],
) -> anyhow::Result<()> {
    let (_, mut writer) = queue.split();
    writer
        .write(OutgoingPacket {
            transaction_id: *tid,
            packet_type,
            payload,
        })
        .await?;
    *tid += 1;
    Ok(())
}

// ===========================================================================
// NVSP message building
// ===========================================================================

/// Build an NVSP message payload (header + data), padded to 8-byte alignment.
pub fn nvsp_payload(message_type: u32, data: &[u8]) -> Vec<u8> {
    let header = protocol::MessageHeader { message_type };
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(data);
    while buf.len() % 8 != 0 {
        buf.push(0);
    }
    buf
}

/// Build an NVSP `Message1SendRndisPacket` payload with header.
pub fn nvsp_rndis_payload(channel_type: u32, section_index: u32, section_size: u32) -> Vec<u8> {
    nvsp_payload(
        protocol::MESSAGE1_TYPE_SEND_RNDIS_PACKET,
        protocol::Message1SendRndisPacket {
            channel_type,
            send_buffer_section_index: section_index,
            send_buffer_section_size: section_size,
        }
        .as_bytes(),
    )
}

/// Send one NVSP in-band message with configurable completion behavior.
pub async fn send_inband_nvsp(
    queue: &mut Queue<GpadlRingMem>,
    tid: &mut u64,
    message_type: u32,
    data: &[u8],
    with_completion: bool,
) -> anyhow::Result<()> {
    let payload = nvsp_payload(message_type, data);
    let packet_type = if with_completion {
        OutgoingPacketType::InBandWithCompletion
    } else {
        OutgoingPacketType::InBandNoCompletion
    };
    write_packet(queue, tid, packet_type, &[&payload]).await
}

// ===========================================================================
// NVSP protocol negotiation
// ===========================================================================

/// Perform full protocol negotiation (version init, NDIS config, NDIS version,
/// receive buffer, send buffer) to reach the ready state.
pub async fn negotiate_to_ready(
    queue: &mut Queue<GpadlRingMem>,
    tid: &mut u64,
    recv_buf_gpadl: GpadlId,
    send_buf_gpadl: GpadlId,
) -> anyhow::Result<()> {
    // Version init.
    let init = protocol::MessageInit {
        protocol_version: protocol::Version::V5 as u32,
        protocol_version2: protocol::Version::V6 as u32,
    };
    send_and_read_completion(queue, tid, protocol::MESSAGE_TYPE_INIT, init.as_bytes()).await?;

    // NDIS config.
    let config = protocol::Message2SendNdisConfig {
        mtu: 1500,
        reserved: 0,
        capabilities: protocol::NdisConfigCapabilities::new(),
    };
    send_and_read_completion(
        queue,
        tid,
        protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
        config.as_bytes(),
    )
    .await?;

    // NDIS version.
    let version = protocol::Message1SendNdisVersion {
        ndis_major_version: 6,
        ndis_minor_version: 30,
    };
    send_and_read_completion(
        queue,
        tid,
        protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
        version.as_bytes(),
    )
    .await?;

    // Receive buffer.
    let msg = protocol::Message1SendReceiveBuffer {
        gpadl_handle: recv_buf_gpadl,
        id: 0,
        reserved: 0,
    };
    send_and_read_completion(
        queue,
        tid,
        protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
        msg.as_bytes(),
    )
    .await?;

    // Send buffer.
    let msg = protocol::Message1SendSendBuffer {
        gpadl_handle: send_buf_gpadl,
        id: 0,
        reserved: 0,
    };
    send_and_read_completion(
        queue,
        tid,
        protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
        msg.as_bytes(),
    )
    .await?;

    Ok(())
}

/// Send RNDIS initialize to transition to RndisState::Operational.
pub async fn rndis_initialize(
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    data_page_start: usize,
    data_page_count: usize,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    let init_request = rndisprot::InitializeRequest {
        request_id: 0,
        major_version: rndisprot::MAJOR_VERSION,
        minor_version: rndisprot::MINOR_VERSION,
        max_transfer_size: 0,
    };
    let rndis_bytes = build_rndis_message(
        rndisprot::MESSAGE_TYPE_INITIALIZE_MSG,
        init_request.as_bytes(),
    );
    send_rndis_gpadirect(
        queue,
        mem,
        &rndis_bytes,
        protocol::CONTROL_CHANNEL_TYPE,
        data_page_start,
        data_page_count,
        tid,
    )
    .await?;

    // Read and discard the RNDIS initialize completion (and any other
    // interleaved messages) so the ring doesn't fill up.
    drain_queue(queue);
    Ok(())
}

/// Send an NVSP InBandWithCompletion message and read the completion,
/// validating that it is well-formed and successful.
async fn send_and_read_completion(
    queue: &mut Queue<GpadlRingMem>,
    tid: &mut u64,
    message_type: u32,
    data: &[u8],
) -> anyhow::Result<()> {
    send_inband_nvsp(queue, tid, message_type, data, true).await?;
    let (mut reader, _) = queue.split();
    let packet = reader.read().await?;
    match &*packet {
        IncomingPacket::Completion(completion) => {
            let mut r = completion.reader();
            let header: protocol::MessageHeader = r.read_plain()?;
            match message_type {
                protocol::MESSAGE_TYPE_INIT => {
                    anyhow::ensure!(
                        header.message_type == protocol::MESSAGE_TYPE_INIT_COMPLETE,
                        "unexpected init completion message type: {}",
                        header.message_type
                    );
                    let c: protocol::MessageInitComplete = r.read_plain()?;
                    anyhow::ensure!(
                        c.status == protocol::Status::SUCCESS,
                        "init completion status not SUCCESS: {:?}",
                        c.status
                    );
                }
                protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER => {
                    anyhow::ensure!(
                        header.message_type == protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER_COMPLETE,
                        "unexpected receive buffer completion message type: {}",
                        header.message_type
                    );
                    let c: protocol::Message1SendReceiveBufferComplete = r.read_plain()?;
                    anyhow::ensure!(
                        c.status == protocol::Status::SUCCESS,
                        "receive buffer completion status not SUCCESS: {:?}",
                        c.status
                    );
                }
                protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER => {
                    anyhow::ensure!(
                        header.message_type == protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER_COMPLETE,
                        "unexpected send buffer completion message type: {}",
                        header.message_type
                    );
                    let c: protocol::Message1SendSendBufferComplete = r.read_plain()?;
                    anyhow::ensure!(
                        c.status == protocol::Status::SUCCESS,
                        "send buffer completion status not SUCCESS: {:?}",
                        c.status
                    );
                }
                _ => {
                    // NDIS config and NDIS version don't have structured
                    // completions — just verify we got a completion packet.
                }
            }
        }
        IncomingPacket::Data(_) => {
            anyhow::bail!("expected completion packet, got data packet");
        }
    }
    Ok(())
}

// ===========================================================================
// RNDIS helpers
// ===========================================================================

/// Build a complete RNDIS message with header + body.
pub fn build_rndis_message(message_type: u32, body: &[u8]) -> Vec<u8> {
    let header = rndisprot::MessageHeader {
        message_type,
        message_length: (size_of::<rndisprot::MessageHeader>() + body.len()) as u32,
    };
    let mut buf = Vec::with_capacity(header.message_length as usize);
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(body);
    buf
}

/// Build an RNDIS OID query message (MESSAGE_TYPE_QUERY_MSG).
pub fn build_rndis_oid_query(oid: rndisprot::Oid, extra_data: &[u8]) -> Vec<u8> {
    let request = rndisprot::QueryRequest {
        request_id: 1,
        oid,
        information_buffer_length: extra_data.len() as u32,
        information_buffer_offset: if extra_data.is_empty() {
            0
        } else {
            size_of::<rndisprot::QueryRequest>() as u32
        },
        device_vc_handle: 0,
    };
    let mut body = Vec::new();
    body.extend_from_slice(request.as_bytes());
    body.extend_from_slice(extra_data);
    build_rndis_message(rndisprot::MESSAGE_TYPE_QUERY_MSG, &body)
}

/// Build an RNDIS OID set message (MESSAGE_TYPE_SET_MSG).
pub fn build_rndis_oid_set(oid: rndisprot::Oid, payload: &[u8]) -> Vec<u8> {
    let request = rndisprot::SetRequest {
        request_id: 1,
        oid,
        information_buffer_length: payload.len() as u32,
        information_buffer_offset: size_of::<rndisprot::SetRequest>() as u32,
        device_vc_handle: 0,
    };
    let mut body = Vec::new();
    body.extend_from_slice(request.as_bytes());
    body.extend_from_slice(payload);
    build_rndis_message(rndisprot::MESSAGE_TYPE_SET_MSG, &body)
}

/// Write raw bytes into guest memory at a given page-aligned offset.
/// Returns the number of bytes written, or None when no bytes can be written.
pub fn write_to_guest(
    mem: &GuestMemory,
    data: &[u8],
    page_start: usize,
    max_pages: usize,
) -> Option<usize> {
    let max_bytes = max_pages * PAGE_SIZE;
    let len = data.len().min(max_bytes);
    if len == 0 {
        return None;
    }
    let base_addr = (page_start * PAGE_SIZE) as u64;
    mem.write_at(base_addr, &data[..len]).ok()?;
    Some(len)
}

/// Send a GpaDirect packet referencing data previously written to guest
/// memory at `page_start`.
pub async fn send_gpadirect(
    queue: &mut Queue<GpadlRingMem>,
    page_start: usize,
    byte_len: usize,
    payload: &[u8],
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    let page_count = byte_len.div_ceil(PAGE_SIZE);
    let pages: Vec<u64> = (page_start..page_start + page_count)
        .map(|p| p as u64)
        .collect();
    let gpa_range = PagedRange::new(0, byte_len, pages.as_slice()).unwrap();
    write_packet(
        queue,
        tid,
        OutgoingPacketType::GpaDirect(&[gpa_range]),
        &[payload],
    )
    .await
}

/// Write RNDIS data to guest memory and send it via GpaDirect with an
/// NVSP `Message1SendRndisPacket` wrapper.
pub async fn send_rndis_gpadirect(
    queue: &mut Queue<GpadlRingMem>,
    mem: &GuestMemory,
    rndis_bytes: &[u8],
    channel_type: u32,
    data_page_start: usize,
    data_page_count: usize,
    tid: &mut u64,
) -> Result<(), anyhow::Error> {
    if let Some(byte_len) = write_to_guest(mem, rndis_bytes, data_page_start, data_page_count) {
        let nvsp = nvsp_rndis_payload(channel_type, 0xffffffff, 0);
        send_gpadirect(queue, data_page_start, byte_len, &nvsp, tid).await?;
    }
    Ok(())
}

// ===========================================================================
// Shared fuzz types
// ===========================================================================

/// Fuzzed RNDIS message with arbitrary header and payload.
#[derive(Arbitrary)]
pub struct StructuredRndisMessage {
    pub header: rndisprot::MessageHeader,
    pub payload: Vec<u8>,
}

/// Fuzzed RNDIS packet message with structured header, packet, and tail.
#[derive(Arbitrary)]
pub struct StructuredRndisPacketMessage {
    pub header: rndisprot::MessageHeader,
    pub packet: rndisprot::Packet,
    pub tail_bytes: Vec<u8>,
}

/// Serialize a [`StructuredRndisPacketMessage`] into a byte vector,
/// fixing up `message_length` to match the actual serialized size.
pub fn serialize_structured_rndis_packet_message(
    rndis: &mut StructuredRndisPacketMessage,
) -> Vec<u8> {
    rndis.header.message_length = (size_of::<rndisprot::MessageHeader>()
        + size_of::<rndisprot::Packet>()
        + rndis.tail_bytes.len()) as u32;
    let mut rndis_bytes = Vec::with_capacity(rndis.header.message_length as usize);
    rndis_bytes.extend_from_slice(rndis.header.as_bytes());
    rndis_bytes.extend_from_slice(rndis.packet.as_bytes());
    rndis_bytes.extend_from_slice(&rndis.tail_bytes);
    rndis_bytes
}

/// Section size used when writing RNDIS data into the send buffer GPADL.
pub const SEND_BUFFER_SECTION_SIZE_BYTES: usize = 6144;

// ===========================================================================
// Arbitrary generators
// ===========================================================================

/// Generate a random [`OutgoingPacketType`] for fuzz actions.
pub fn arbitrary_outgoing_packet_type(
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<OutgoingPacketType<'static>> {
    Ok(match u.arbitrary::<u8>()? % 3 {
        0 => OutgoingPacketType::InBandNoCompletion,
        1 => OutgoingPacketType::InBandWithCompletion,
        _ => OutgoingPacketType::Completion,
    })
}

/// Generate a random [`protocol::Message1SendReceiveBuffer`] with an
/// arbitrary GPADL handle.
pub fn arbitrary_send_receive_buffer_message(
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<protocol::Message1SendReceiveBuffer> {
    Ok(protocol::Message1SendReceiveBuffer {
        gpadl_handle: GpadlId(u.arbitrary::<u32>()?),
        id: u.arbitrary::<u16>()?,
        reserved: u.arbitrary::<u16>()?,
    })
}

/// Generate a random [`protocol::Message1SendSendBuffer`] with an
/// arbitrary GPADL handle.
pub fn arbitrary_send_send_buffer_message(
    u: &mut Unstructured<'_>,
) -> arbitrary::Result<protocol::Message1SendSendBuffer> {
    Ok(protocol::Message1SendSendBuffer {
        gpadl_handle: GpadlId(u.arbitrary::<u32>()?),
        id: u.arbitrary::<u16>()?,
        reserved: u.arbitrary::<u16>()?,
    })
}

// ===========================================================================
// NIC setup
// ===========================================================================

/// Set up a NIC with the specified page layout, returning a ready-to-use
/// queue and GPADL IDs.
///
/// The fuzz loop callback receives the setup and can run arbitrary actions.
pub async fn setup_fuzz_nic<F, Fut>(
    driver: &pal_async::DefaultDriver,
    layout: &PageLayout,
    fuzz_loop: F,
) -> anyhow::Result<()>
where
    F: FnOnce(FuzzNicSetup) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let total_guest_pages = layout.total_pages();
    let recv_buf_page_count = RECV_BUF_PAGES;
    let send_buf_page_count = layout.send_buf_pages;
    let mock_vmbus = CapturingMockVmbus::new(total_guest_pages);
    let mem = mock_vmbus.memory.clone();

    let nic = Nic::builder().build(
        &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
        Guid::new_random(),
        Box::new(NullEndpoint::new()),
        [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into(),
        0,
    );

    let channel = offer_channel(driver, &mock_vmbus, nic)
        .await
        .expect("offer_channel failed");

    let offer_input = mock_vmbus.take_offer_input().await;

    let gpadl_map = GpadlMap::new();
    let mut next_page = 0usize;
    let mut next_gpadl_id = 1u32;

    // Allocate a GPADL region, register it with the device and local map.
    let alloc_gpadl =
        |page_count: usize, next_page: &mut usize, next_gpadl_id: &mut u32| -> GpadlAlloc {
            let gpadl_id = GpadlId(*next_gpadl_id);
            *next_gpadl_id += 1;
            let pages: Vec<u64> = std::iter::once((page_count * PAGE_SIZE) as u64)
                .chain((*next_page..*next_page + page_count).map(|p| p as u64))
                .collect();
            *next_page += page_count;
            GpadlAlloc { gpadl_id, pages }
        };

    // Ring buffer (4 pages).
    let ring = alloc_gpadl(4, &mut next_page, &mut next_gpadl_id);
    let ring_gpadl_id = ring.gpadl_id;
    assert!(
        offer_input
            .request_send
            .call(
                ChannelRequest::Gpadl,
                GpadlRequest {
                    id: ring.gpadl_id,
                    count: 1,
                    buf: ring.pages.clone(),
                },
            )
            .await
            .expect("ring gpadl request"),
        "ring gpadl was not accepted"
    );
    gpadl_map.add(
        ring.gpadl_id,
        MultiPagedRangeBuf::from_range_buffer(1, ring.pages).unwrap(),
    );

    // Receive buffer.
    let recv = alloc_gpadl(recv_buf_page_count, &mut next_page, &mut next_gpadl_id);
    let recv_buf_gpadl_id = recv.gpadl_id;
    assert!(
        offer_input
            .request_send
            .call(
                ChannelRequest::Gpadl,
                GpadlRequest {
                    id: recv.gpadl_id,
                    count: 1,
                    buf: recv.pages.clone(),
                },
            )
            .await
            .expect("recv buf gpadl request"),
        "recv buf gpadl was not accepted"
    );
    gpadl_map.add(
        recv.gpadl_id,
        MultiPagedRangeBuf::from_range_buffer(1, recv.pages).unwrap(),
    );

    // Send buffer.
    let send = alloc_gpadl(send_buf_page_count, &mut next_page, &mut next_gpadl_id);
    let send_buf_gpadl_id = send.gpadl_id;
    assert!(
        offer_input
            .request_send
            .call(
                ChannelRequest::Gpadl,
                GpadlRequest {
                    id: send.gpadl_id,
                    count: 1,
                    buf: send.pages.clone(),
                },
            )
            .await
            .expect("send buf gpadl request"),
        "send buf gpadl was not accepted"
    );
    gpadl_map.add(
        send.gpadl_id,
        MultiPagedRangeBuf::from_range_buffer(1, send.pages).unwrap(),
    );

    // Open the channel.
    let host_to_guest_event = Arc::new(SlimEvent::new());
    let host_to_guest_interrupt = {
        let event = host_to_guest_event.clone();
        Interrupt::from_fn(move || event.signal())
    };

    let open_request = OpenRequest {
        open_data: OpenData {
            target_vp: 0,
            ring_offset: 2,
            ring_gpadl_id,
            event_flag: 1,
            connection_id: 1,
            user_data: UserDefinedData::new_zeroed(),
        },
        interrupt: host_to_guest_interrupt,
        use_confidential_ring: false,
        use_confidential_external_memory: false,
    };

    let open_result = offer_input
        .request_send
        .call::<_, _, bool>(ChannelRequest::Open, open_request)
        .await
        .expect("open request");

    assert!(
        open_result,
        "channel open failed unexpectedly in fuzz setup"
    );

    channel.start();

    let guest_to_host_interrupt = offer_input.event.clone();
    let gpadl_map_view = gpadl_map.view();
    let done = Arc::new(AtomicBool::new(false));
    let raw_channel = gpadl_test_guest_channel(
        &mem,
        &gpadl_map_view,
        ring_gpadl_id,
        2,
        host_to_guest_event,
        guest_to_host_interrupt,
        done,
    );
    let queue = Queue::new(raw_channel).unwrap();

    let setup = FuzzNicSetup {
        queue,
        mem,
        recv_buf_gpadl_id,
        send_buf_gpadl_id,
    };

    fuzz_loop(setup).await?;

    // Clean up: close the channel.
    let _ = offer_input
        .request_send
        .call::<_, _, ()>(ChannelRequest::Close, ())
        .await;

    Ok(())
}

// ===========================================================================
// Fuzz loop boilerplate
// ===========================================================================

/// Result of setting up a NIC on a mock VMBus, ready for fuzzing.
pub struct FuzzNicSetup {
    pub queue: Queue<GpadlRingMem>,
    /// Guest memory backing the VMBus ring and buffers.
    pub mem: GuestMemory,
    pub recv_buf_gpadl_id: GpadlId,
    pub send_buf_gpadl_id: GpadlId,
}

/// Try reading a single packet from the queue, returning true iff it is a completion packet.
pub fn try_read_one_completion(queue: &mut Queue<GpadlRingMem>) -> bool {
    let (mut reader, _) = queue.split();
    match reader.try_read() {
        Ok(packet) => matches!(&*packet, IncomingPacket::Completion(_)),
        Err(_) => false,
    }
}

/// Drain all pending packets from the queue. Useful to avoid ring-full
/// deadlocks between fuzz actions.
pub fn drain_queue(queue: &mut Queue<GpadlRingMem>) {
    loop {
        let (mut reader, _) = queue.split();
        if reader.try_read().is_err() {
            break;
        }
    }
}

/// Run the standard fuzz loop boilerplate: set up a NIC, run a fuzz
/// callback with a timeout, and report the outcome.
///
/// This eliminates the repeated `do_fuzz` / `fuzz_target!` pattern
/// across fuzz targets.
pub fn run_fuzz_loop<F>(input: &[u8], layout: &PageLayout, fuzz_loop: F)
where
    F: for<'a> FnOnce(
        &'a mut Unstructured<'_>,
        FuzzNicSetup,
    )
        -> std::pin::Pin<Box<dyn Future<Output = Result<(), anyhow::Error>> + 'a>>,
{
    xtask_fuzz::init_tracing_if_repro();

    let mut u = Unstructured::new(input);
    pal_async::DefaultPool::run_with(async |driver| {
        setup_fuzz_nic(&driver, layout, |setup| async {
            let fuzz_result = mesh::CancelContext::new()
                .with_timeout(Duration::from_millis(500))
                .until_cancelled(fuzz_loop(&mut u, setup))
                .await;

            match fuzz_result {
                Ok(Ok(())) => {
                    xtask_fuzz::fuzz_eprintln!("test case exhausted arbitrary data");
                }
                Ok(Err(_e)) => {
                    xtask_fuzz::fuzz_eprintln!("fuzz loop error (expected for malformed input)");
                }
                Err(_) => {
                    xtask_fuzz::fuzz_eprintln!("fuzz loop timed out");
                }
            }
            Ok(())
        })
        .await
    })
    .expect("fuzz pool failed to run");
}
