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
//! The fuzz input is parsed as a sequence of packets. The first byte
//! selects the DMA mode (DirectDma or BounceBuffer). Each subsequent
//! packet is described by a 14-byte header plus 2-byte segment lengths.
//!
//! ## Coverage design
//!
//! - Header lengths (l2/l3/l4) are clamped to realistic ranges so LSO
//!   packets pass the `header_len <= PAGE_SIZE` check and reach the
//!   inner header-split, bounce-buffer, and coalescing logic.
//! - Segment counts range from 1 to 64, covering the >31 segment
//!   coalescing code path.
//! - Both DirectDma and BounceBuffer modes are exercised.
//!
//! ## Trust boundary
//!
//! The guest provides TX segments via netvsp → net_mana. A malicious
//! guest could provide arbitrary metadata. This fuzzer validates that
//! `handle_tx` never panics regardless of input.

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
use net_backend::null::NullEndpoint;
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

/// Header: 1 byte mode + 14 byte packet header + 2 byte segment len.
const MIN_INPUT_BYTES: usize = 17;

/// Maximum segments per packet.
const MAX_SEGMENTS: u8 = 64;

/// Parse one fuzzed packet from the input bytes.
///
/// Packet wire format (little-endian):
///   [0]     segment_count (1..=MAX_SEGMENTS)
///   [1]     flags (TxFlags bits)
///   [2]     l2_len_raw — clamped to [0, 64] for realism
///   [3]     l3_len_raw — clamped to [0, 255] for realism
///   [4]     l4_len_raw — clamped to [0, 64] for realism
///   [5..7]  max_tcp_segment_size (LE u16)
///   [7..9]  total_len_lo (LE u16), used as total_len (capped to 65535)
///   [9..11] seg_len_base (LE u16) — base segment length for all segments
///   [11..13] seg_len_fuzz (LE u16) — XOR'd with base for first segment
///   [13]    extra_flags: bit0 = force_large_total_len
///   For each segment beyond the first (segment_count - 1 times):
///     [2 bytes] delta (LE u16) — XOR'd with seg_len_base
///
/// Returns (segments, remaining_input).
fn parse_packet(input: &[u8], tx_id: u32, guest_mem_size: u64) -> Option<(Vec<TxSegment>, &[u8])> {
    if input.len() < 14 {
        return None;
    }

    let segment_count = input[0].max(1).min(MAX_SEGMENTS);
    let flags = TxFlags::from(input[1]);
    // Clamp header lengths to realistic ranges so LSO path is reachable
    let l2_len = input[2] & 0x3F; // 0..63 (typ: 14)
    let l3_len = input[3] as u16; // 0..255 (typ: 20 or 40)
    let l4_len = input[4] & 0x3F; // 0..63 (typ: 20)
    let max_tcp_segment_size = u16::from_le_bytes([input[5], input[6]]);
    let total_len_lo = u16::from_le_bytes([input[7], input[8]]) as u32;
    let seg_len_base = u16::from_le_bytes([input[9], input[10]]) as u32;
    let seg_len_fuzz = u16::from_le_bytes([input[11], input[12]]) as u32;
    let extra_flags = input[13];

    // Allow the fuzzer to exercise large (but not OOM-large) packets
    let total_len = if extra_flags & 1 != 0 {
        total_len_lo.saturating_mul(16).min(512 * 1024)
    } else {
        total_len_lo
    };

    let per_seg_data_start = 14;
    let needed = per_seg_data_start + ((segment_count as usize).saturating_sub(1)) * 2;
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
        let seg_len = if i == 0 {
            seg_len_base ^ seg_len_fuzz
        } else {
            let off = per_seg_data_start + (i - 1) * 2;
            let delta = u16::from_le_bytes([input[off], input[off + 1]]) as u32;
            seg_len_base ^ delta
        };

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

    if input.len() < MIN_INPUT_BYTES {
        return;
    }

    // First byte selects DMA mode: even = DirectDma, odd = BounceBuffer
    let dma_mode = if input[0] & 1 == 0 {
        GuestDmaMode::DirectDma
    } else {
        GuestDmaMode::BounceBuffer
    };
    let input = &input[1..];

    pal_async::DefaultPool::run_with(async |driver| {
        // -- Deterministic device setup --
        let pages = 512;
        let allow_dma = dma_mode == GuestDmaMode::DirectDma;
        let mem = DeviceTestMemory::new(pages, allow_dma, "fuzz_net_mana_tx_avail");
        let payload_mem = mem.payload_mem();
        let msi_conn = MsiConnection::new();
        let gdma_device = gdma::GdmaDevice::new(
            &VmTaskDriverSource::new(SingleDriverBackend::new(driver.clone())),
            mem.guest_memory(),
            msi_conn.target(),
            vec![gdma::VportConfig {
                mac_address: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into(),
                endpoint: Box::new(NullEndpoint::new()),
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
        let mut endpoint = ManaEndpoint::new(driver.clone(), vport, dma_mode).await;

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

        let guest_mem_size = (pages as u64) * 4096;

        fuzz_eprintln!(
            "fuzz: setup complete, dma_mode={:?}, parsing packets from {} bytes",
            dma_mode,
            input.len()
        );

        // -- Fuzz loop --
        let fuzz_result = mesh::CancelContext::new()
            .with_timeout(Duration::from_millis(500))
            .until_cancelled(async {
                let mut remaining = input;
                let mut tx_id = 1u32;
                let mut tx_done = vec![TxId(0); 64];

                while remaining.len() >= 14 {
                    let Some((segments, rest)) = parse_packet(remaining, tx_id, guest_mem_size)
                    else {
                        break;
                    };
                    remaining = rest;
                    tx_id = tx_id.wrapping_add(1);

                    // Submit the fuzzed packet.
                    let _ = queue.tx_avail(&segments);

                    // Drain completions to keep posted_tx from filling up.
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
