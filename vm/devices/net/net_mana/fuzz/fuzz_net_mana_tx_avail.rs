// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for net_mana TX submission (`tx_avail` + `handle_tx`).
//!
//! This fuzzer exercises the guest → driver TX path by constructing
//! fuzzed `TxSegment` arrays and passing them to `ManaQueue::tx_avail()`.
//! This tests the driver's handling of adversarial guest-provided packet
//! metadata: segment counts, packet lengths, header lengths, LSO flags,
//! segment coalescing, and bounce buffer logic.
//!
//! The fuzz input is parsed as a sequence of packets, each described by
//! a compact header (12 bytes) plus per-segment lengths (4 bytes each).
//!
//! ## Trust boundary
//!
//! The guest provides TX segments via netvsp → net_mana. A malicious
//! guest could provide arbitrary metadata (segment_count, l2/l3/l4_len,
//! flags, GPAs, lengths). This fuzzer validates that `handle_tx` never
//! panics or causes memory safety issues regardless of input.

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

use chipset_device::mmio::ExternallyManagedMmioIntercepts;
use gdma_defs::bnic::ManaQueryDeviceCfgResp;
use mana_driver::mana::ManaDevice;
use net_backend::Endpoint;
use net_backend::Queue;
use net_backend::QueueConfig;
use net_backend::RxId;
use net_backend::TxFlags;
use net_backend::TxId;
use net_backend::TxMetadata;
use net_backend::TxSegment;
use net_backend::TxSegmentType;
use net_backend::loopback::LoopbackEndpoint;
use net_mana::GuestDmaMode;
use net_mana::ManaEndpoint;
use pci_core::msi::MsiConnection;
use std::future::poll_fn;
use std::time::Duration;
use user_driver_emulated_mock::DeviceTestMemory;
use user_driver_emulated_mock::EmulatedDevice;
use vmcore::vm_task::SingleDriverBackend;
use vmcore::vm_task::VmTaskDriverSource;
use xtask_fuzz::fuzz_eprintln;
use xtask_fuzz::fuzz_target;

/// Minimum bytes to describe one packet: 12 byte header + 4 byte segment len.
const MIN_PACKET_BYTES: usize = 16;

/// Maximum segments per packet (clamped to avoid huge allocations).
const MAX_SEGMENTS: u8 = 64;

/// Parse one fuzzed packet's TxSegments from the input bytes.
///
/// Packet wire format (little-endian):
///   [0]    segment_count (1..=MAX_SEGMENTS, clamped)
///   [1]    flags (TxFlags bits)
///   [2]    l2_len
///   [3..5] l3_len (LE u16)
///   [5]    l4_len
///   [6..8] max_tcp_segment_size (LE u16)
///   [8..12] total_len (LE u32)
///   For each segment (segment_count times):
///     [4 bytes] segment_len (LE u32)
///
/// Returns (segments, remaining_input).
fn parse_packet(input: &[u8], tx_id: u32, guest_mem_size: u64) -> Option<(Vec<TxSegment>, &[u8])> {
    if input.len() < MIN_PACKET_BYTES {
        return None;
    }

    let segment_count = input[0].max(1).min(MAX_SEGMENTS);
    let flags = TxFlags::from(input[1]);
    let l2_len = input[2];
    let l3_len = u16::from_le_bytes([input[3], input[4]]);
    let l4_len = input[5];
    let max_tcp_segment_size = u16::from_le_bytes([input[6], input[7]]);
    let total_len = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);

    let seg_data_start = 12;
    let needed = seg_data_start + (segment_count as usize) * 4;
    if input.len() < needed {
        return None;
    }

    let meta = TxMetadata {
        id: TxId(tx_id),
        segment_count,
        flags,
        len: total_len,
        l2_len,
        l3_len,
        l4_len,
        max_tcp_segment_size,
    };

    let mut segments = Vec::with_capacity(segment_count as usize);
    let mut gpa_offset: u64 = 0;

    for i in 0..segment_count as usize {
        let off = seg_data_start + i * 4;
        let seg_len =
            u32::from_le_bytes([input[off], input[off + 1], input[off + 2], input[off + 3]]);

        // Constrain GPA to valid guest memory range.
        let gpa = gpa_offset % guest_mem_size;
        gpa_offset = gpa_offset.wrapping_add(seg_len as u64);

        let ty = if i == 0 {
            TxSegmentType::Head(meta.clone())
        } else {
            TxSegmentType::Tail
        };

        segments.push(TxSegment {
            ty,
            gpa,
            len: seg_len,
        });
    }

    Some((segments, &input[needed..]))
}

fn do_fuzz(input: &[u8]) {
    xtask_fuzz::init_tracing_if_repro();

    if input.len() < MIN_PACKET_BYTES {
        return;
    }

    pal_async::DefaultPool::run_with(async |driver| {
        // -- Deterministic device setup --
        let pages = 512;
        let mem = DeviceTestMemory::new(pages, true, "fuzz_net_mana_tx_avail");
        let payload_mem = mem.payload_mem();
        let msi_conn = MsiConnection::new();
        let gdma_device = gdma::GdmaDevice::new(
            &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
            mem.guest_memory(),
            msi_conn.target(),
            vec![gdma::VportConfig {
                mac_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into(),
                endpoint: Box::new(LoopbackEndpoint::new()),
            }],
            &mut ExternallyManagedMmioIntercepts,
        );
        let device = EmulatedDevice::new(gdma_device, msi_conn, mem.dma_client());

        let dev_config = ManaQueryDeviceCfgResp {
            pf_cap_flags1: 0.into(),
            pf_cap_flags2: 0,
            pf_cap_flags3: 0,
            pf_cap_flags4: 0,
            max_num_vports: 1,
            reserved: 0,
            max_num_eqs: 64,
        };

        let Ok(mana_device) = ManaDevice::new(&driver, device, 1, 1, None).await else {
            return;
        };
        let Ok(vport) = mana_device.new_vport(0, None, &dev_config).await else {
            return;
        };
        let mut endpoint = ManaEndpoint::new(driver.clone(), vport, GuestDmaMode::DirectDma).await;

        let pool = net_backend::tests::Bufs::new(payload_mem.clone());
        let initial_rx: Vec<RxId> = (1..32).map(RxId).collect();
        let mut queue_vec: Vec<Box<dyn Queue>> = Vec::new();
        if endpoint
            .get_queues(
                vec![QueueConfig {
                    pool: Box::new(pool),
                    initial_rx: &initial_rx,
                    driver: Box::new(driver.clone()),
                }],
                None,
                &mut queue_vec,
            )
            .await
            .is_err()
        {
            return;
        };

        let queue = &mut *queue_vec[0];

        // Guest memory size for GPA clamping.
        let guest_mem_size = (pages as u64) * 4096;

        fuzz_eprintln!(
            "fuzz: setup complete, parsing packets from {} bytes",
            input.len()
        );

        // -- Fuzz loop: parse packets from input and submit them --
        let fuzz_result = mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(500))
            .until_cancelled(async {
                let mut remaining = input;
                let mut tx_id = 1u32;
                let mut tx_done = vec![TxId(0); 64];

                while remaining.len() >= MIN_PACKET_BYTES {
                    let Some((segments, rest)) = parse_packet(remaining, tx_id, guest_mem_size)
                    else {
                        break;
                    };
                    remaining = rest;
                    tx_id = tx_id.wrapping_add(1);

                    fuzz_eprintln!(
                        "fuzz: tx_avail with {} segments, flags={:#x}",
                        segments.len(),
                        segments
                            .first()
                            .map(|s| if let TxSegmentType::Head(m) = &s.ty {
                                u8::from(m.flags)
                            } else {
                                0
                            })
                            .unwrap_or(0)
                    );

                    // Submit the fuzzed packet. Errors are expected and fine.
                    let _ = queue.tx_avail(&segments);

                    // Drain completions from the real GDMA emulator path.
                    // This keeps posted_tx from filling up.
                    let _ = mesh::CancelContext::new()
                        .with_timeout(Duration::from_millis(5))
                        .until_cancelled(poll_fn(|cx| queue.poll_ready(cx)))
                        .await;
                    let _ = queue.tx_poll(&mut tx_done);
                }
            })
            .await;
        let _ = fuzz_result;

        drop(queue_vec);
        endpoint.stop().await;
    });
}

fuzz_target!(|input: &[u8]| {
    do_fuzz(input);
});
