// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Resource resolver for [`GdmaTestDeviceHandle`].

use async_trait::async_trait;
use futures::StreamExt;
use gdma::GdmaDevice;
use gdma::test_helpers::InjectEqeError;
use gdma::test_helpers::hwc_eq_injector;
use gdma::test_helpers::resolve_vports;
use gdma_defs::EqeDataReconfig;
use gdma_defs::GDMA_EQE_HWC_RECONFIG_DATA;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT;
use gdma_defs::HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT;
use gdma_resources::GdmaTestDeviceHandle;
use gdma_resources::GdmaTestRequest;
use pal_async::task::Spawn;
use pci_resources::ResolvePciDeviceHandleParams;
use pci_resources::ResolvedPciDevice;
use thiserror::Error;
use vm_resource::AsyncResolveResource;
use vm_resource::ResourceResolver;
use vm_resource::declare_static_async_resolver;
use vm_resource::kind::PciDeviceHandleKind;
use zerocopy::IntoBytes;

/// Resource resolver for [`GdmaTestDeviceHandle`].
///
/// Creates a standard GDMA device and spawns a background task that translates
/// test requests into EQEs injected directly into the HWC EQ. The task exits
/// when test control is shut down.
pub struct GdmaTestDeviceResolver;

declare_static_async_resolver! {
    GdmaTestDeviceResolver,
    (PciDeviceHandleKind, GdmaTestDeviceHandle),
}

/// An error handling a GDMA test-control request.
#[derive(Debug, Error)]
enum TestRequestError {
    #[error("vport index {vport} does not fit in the 24-bit EQE field")]
    VportTooLarge { vport: u32 },
    #[error(transparent)]
    Inject(#[from] InjectEqeError),
}

fn encode_vport_link_state(
    vport: u32,
    connected: bool,
) -> Result<EqeDataReconfig, TestRequestError> {
    if vport > 0x00ff_ffff {
        return Err(TestRequestError::VportTooLarge { vport });
    }

    let vport = vport.to_le_bytes();
    Ok(EqeDataReconfig {
        data: [vport[0], vport[1], vport[2]],
        data_type: if connected {
            HWC_DATA_TYPE_HW_VPORT_LINK_CONNECT
        } else {
            HWC_DATA_TYPE_HW_VPORT_LINK_DISCONNECT
        },
        reserved1: [0; 8],
    })
}

#[async_trait]
impl AsyncResolveResource<PciDeviceHandleKind, GdmaTestDeviceHandle> for GdmaTestDeviceResolver {
    type Output = ResolvedPciDevice;
    type Error = gdma::resolver::Error;

    async fn resolve(
        &self,
        resolver: &ResourceResolver,
        resource: GdmaTestDeviceHandle,
        input: ResolvePciDeviceHandleParams<'_>,
    ) -> Result<Self::Output, Self::Error> {
        let vports = resolve_vports(resolver, resource.vports).await?;
        let device = GdmaDevice::new(
            input.driver_source,
            input.dma_target.guest_memory().clone(),
            input.dma_target.msi_target(),
            vports,
            input.register_mmio,
        );

        let inject_eqe = hwc_eq_injector(&device);
        let mut request_recv = resource.request_recv;
        input
            .driver_source
            .simple()
            .spawn("gdma-test-control", async move {
                while let Some(rpc) = request_recv.next().await {
                    let mut shutdown = false;
                    rpc.handle_failable(async |request| match request {
                        GdmaTestRequest::Shutdown => {
                            shutdown = true;
                            Ok::<(), TestRequestError>(())
                        }
                        GdmaTestRequest::VportLinkState { vport, connected } => {
                            let data = encode_vport_link_state(vport, connected)?;
                            inject_eqe(GDMA_EQE_HWC_RECONFIG_DATA, data.as_bytes())?;
                            Ok(())
                        }
                    })
                    .await;
                    if shutdown {
                        break;
                    }
                }
            })
            .detach();

        Ok(device.into())
    }
}
