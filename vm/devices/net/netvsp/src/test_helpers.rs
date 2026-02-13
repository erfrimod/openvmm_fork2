// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NetVSP test helpers.
//!
//! These are used both by unit tests and by the fuzzer.

// Fuzzers do not use all the code here, but unit tests should.
#![allow(dead_code)]

use async_trait::async_trait;
use guestmem::GuestMemory;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use vmbus_channel::bus::OfferInput;
use vmbus_channel::bus::OfferResources;
use vmbus_channel::bus::ParentBus;
use vmbus_channel::gpadl::GpadlId;
use vmbus_channel::gpadl::GpadlMapView;
use vmbus_channel::gpadl_ring::AlignedGpadlView;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_channel::ChannelClosed;
use vmbus_channel::RawAsyncChannel;
use vmbus_channel::SignalVmbusChannel;
use vmbus_ring::IncomingRing;
use vmbus_ring::OutgoingRing;
use vmbus_ring::PAGE_SIZE;
use vmcore::interrupt::Interrupt;
use vmcore::slim_event::SlimEvent;

/// A [`SignalVmbusChannel`] implementation for test guest channels that
/// supports cooperative shutdown via a shared `done` flag.
pub struct EventWithDone {
    /// Interrupt to signal the remote (host) side.
    pub remote_interrupt: Interrupt,
    /// Event to wait on for local (guest) signals from the host.
    pub local_event: Arc<SlimEvent>,
    /// When set to true, `poll_for_signal` returns `ChannelClosed`.
    pub done: Arc<AtomicBool>,
}

impl SignalVmbusChannel for EventWithDone {
    fn signal_remote(&self) {
        self.remote_interrupt.deliver();
    }

    fn poll_for_signal(&self, cx: &mut Context<'_>) -> Poll<Result<(), ChannelClosed>> {
        if self.done.load(Ordering::Relaxed) {
            return Err(ChannelClosed).into();
        }
        self.local_event.poll_wait(cx).map(Ok)
    }
}

/// Create the incoming and outgoing rings for a guest-side test channel backed
/// by a GPADL.
pub fn make_test_guest_rings(
    mem: &GuestMemory,
    gpadl_map: &GpadlMapView,
    gpadl_id: GpadlId,
    ring_offset: u32,
) -> (IncomingRing<GpadlRingMem>, OutgoingRing<GpadlRingMem>) {
    let gpadl = AlignedGpadlView::new(gpadl_map.map(gpadl_id).unwrap()).unwrap();
    let (out_gpadl, in_gpadl) = match gpadl.split(ring_offset) {
        Ok(gpadls) => gpadls,
        Err(_) => panic!("Failed gpadl.split"),
    };
    (
        IncomingRing::new(GpadlRingMem::new(in_gpadl, mem).unwrap()).unwrap(),
        OutgoingRing::new(GpadlRingMem::new(out_gpadl, mem).unwrap()).unwrap(),
    )
}

/// Build a [`RawAsyncChannel`] backed by GPADL ring memory, suitable for
/// constructing a guest-side [`vmbus_async::queue::Queue`].
pub fn gpadl_test_guest_channel(
    mem: &GuestMemory,
    gpadl_map: &GpadlMapView,
    gpadl_id: GpadlId,
    ring_offset: u32,
    host_to_guest_event: Arc<SlimEvent>,
    guest_to_host_interrupt: Interrupt,
    done: Arc<AtomicBool>,
) -> RawAsyncChannel<GpadlRingMem> {
    let (in_ring, out_ring) = make_test_guest_rings(mem, gpadl_map, gpadl_id, ring_offset);
    RawAsyncChannel {
        in_ring,
        out_ring,
        signal: Box::new(EventWithDone {
            local_event: host_to_guest_event,
            remote_interrupt: guest_to_host_interrupt,
            done,
        }),
    }
}

/// A minimal [`ParentBus`] implementation that captures a single
/// [`OfferInput`]. Useful for fuzzers and simple tests that need direct access
/// to the channel request sender.
#[derive(Clone)]
pub struct CapturingMockVmbus {
    /// The guest memory backing the VMBus channel.
    pub memory: GuestMemory,
    offer_input: Arc<futures::lock::Mutex<Option<OfferInput>>>,
}

impl CapturingMockVmbus {
    /// Create a new mock VMBus with `guest_page_count` pages of guest memory.
    pub fn new(guest_page_count: usize) -> Self {
        Self {
            memory: GuestMemory::allocate(guest_page_count * PAGE_SIZE),
            offer_input: Arc::new(futures::lock::Mutex::new(None)),
        }
    }

    /// Take the captured [`OfferInput`], panicking if none has been stored.
    pub async fn take_offer_input(&self) -> OfferInput {
        self.offer_input.lock().await.take().expect("no offer input")
    }
}

#[async_trait]
impl ParentBus for CapturingMockVmbus {
    async fn add_child(&self, request: OfferInput) -> anyhow::Result<OfferResources> {
        *self.offer_input.lock().await = Some(request);
        Ok(OfferResources::new(self.memory.clone(), None))
    }
    fn clone_bus(&self) -> Box<dyn ParentBus> {
        Box::new(self.clone())
    }
    fn use_event(&self) -> bool {
        false
    }
}
