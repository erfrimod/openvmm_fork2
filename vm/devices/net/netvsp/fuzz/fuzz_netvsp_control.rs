// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fuzzer for NVSP control messages processed by the NetVSP implementation.
//!
//! This fuzzer exercises the NVSP protocol state machine by sending arbitrary
//! sequences of NVSP control messages through a VMBus channel to a NetVSP
//! instance. It can optionally perform a well-formed protocol negotiation
//! first (version init, NDIS config, NDIS version, receive/send buffer setup)
//! before sending fuzzed messages, or skip directly to sending arbitrary
//! messages to test how NetVSP handles unexpected or malformed protocol
//! sequences.

#![cfg_attr(all(target_os = "linux", target_env = "gnu"), no_main)]

#[path = "fuzz_helpers.rs"]
#[allow(dead_code)]
mod fuzz_helpers;

use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use fuzz_helpers::PageLayout;
use fuzz_helpers::drain_queue;
use fuzz_helpers::negotiate_to_ready;
use fuzz_helpers::run_fuzz_loop;
use fuzz_helpers::send_inband_nvsp;
use fuzz_helpers::try_read_one_completion;
use fuzz_helpers::write_packet;
use netvsp::protocol;
use vmbus_async::queue::Queue;
use vmbus_channel::gpadl_ring::GpadlRingMem;
use vmbus_ring::OutgoingPacketType;
use xtask_fuzz::fuzz_target;
use zerocopy::IntoBytes;

const LAYOUT: PageLayout = PageLayout {
    send_buf_pages: 1,
    data_pages: 0,
};

// ---- Fuzz actions ----

/// Actions the fuzzer can take after (optional) protocol negotiation.
#[derive(Arbitrary)]
enum FuzzAction {
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
    /// Send a well-formed Init message with arbitrary version.
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
    /// Send a revoke receive buffer message.
    RevokeReceiveBuffer {
        msg: protocol::Message1RevokeReceiveBuffer,
    },
    /// Send a revoke send buffer message.
    RevokeSendBuffer {
        msg: protocol::Message1RevokeSendBuffer,
    },
    /// Send a switch data path message.
    SwitchDataPath {
        msg: protocol::Message4SwitchDataPath,
    },
    /// Send a subchannel request.
    SubChannelRequest {
        request: protocol::Message5SubchannelRequest,
    },
    /// Send an OID query.
    OidQueryEx { msg: protocol::Message5OidQueryEx },
    /// Read a completion/response from the host.
    ReadCompletion,
}

/// Execute one fuzz action by sending a message through the vmbus channel.
async fn execute_action(
    u: &mut Unstructured<'_>,
    queue: &mut Queue<GpadlRingMem>,
    transaction_id: &mut u64,
) -> Result<(), anyhow::Error> {
    let action = u.arbitrary::<FuzzAction>()?;
    match action {
        FuzzAction::SendRawPacket {
            packet_type,
            payload,
        } => {
            write_packet(queue, transaction_id, packet_type, &[&payload]).await?;
        }
        FuzzAction::SendRawInBand {
            message_type,
            payload: raw_payload,
            with_completion,
        } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                message_type,
                &raw_payload,
                with_completion,
            )
            .await?;
        }
        FuzzAction::SendInit { init } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE_TYPE_INIT,
                init.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SendNdisVersion { version } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE1_TYPE_SEND_NDIS_VERSION,
                version.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SendNdisConfig { config } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE2_TYPE_SEND_NDIS_CONFIG,
                config.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SendReceiveBuffer { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE1_TYPE_SEND_RECEIVE_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SendSendBuffer { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE1_TYPE_SEND_SEND_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::RevokeReceiveBuffer { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE1_TYPE_REVOKE_RECEIVE_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::RevokeSendBuffer { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE1_TYPE_REVOKE_SEND_BUFFER,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SwitchDataPath { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE4_TYPE_SWITCH_DATA_PATH,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::SubChannelRequest { request } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE5_TYPE_SUB_CHANNEL,
                request.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::OidQueryEx { msg } => {
            send_inband_nvsp(
                queue,
                transaction_id,
                protocol::MESSAGE5_TYPE_OID_QUERY_EX,
                msg.as_bytes(),
                true,
            )
            .await?;
        }
        FuzzAction::ReadCompletion => {
            // Try to read a completion from the host side. This is important
            // for forward progress of various code paths.
            let _ = try_read_one_completion(queue);
        }
    }
    Ok(())
}

fuzz_target!(|input: &[u8]| {
    run_fuzz_loop(input, &LAYOUT, |u, setup| {
        Box::pin(async move {
            let mut queue = setup.queue;
            let mut tid = 1u64;

            // 90% of the time, perform a well-formed protocol negotiation first.
            // This gets us into the active/ready state where more interesting
            // message processing occurs.
            if u.ratio(9, 10)? {
                negotiate_to_ready(
                    &mut queue,
                    &mut tid,
                    setup.recv_buf_gpadl_id,
                    setup.send_buf_gpadl_id,
                )
                .await?;
            }

            // Now send arbitrary fuzz actions until the input is exhausted.
            while !u.is_empty() {
                execute_action(u, &mut queue, &mut tid).await?;
                drain_queue(&mut queue);
            }
            Ok(())
        })
    });
});
