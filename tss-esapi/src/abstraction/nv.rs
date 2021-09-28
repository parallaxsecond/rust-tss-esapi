// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;

use crate::{
    constants::{tss::*, CapabilityType, PropertyTag},
    handles::{NvIndexHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::resource_handles::NvAuth,
    nv::storage::NvPublic,
    structures::{CapabilityData, Name},
    Context, Error, Result, WrapperErrorKind,
};

/// Allows reading an NV Index completely, regardless of the max TPM NV buffer size
pub fn read_full(
    context: &mut Context,
    auth_handle: NvAuth,
    nv_index_handle: NvIndexTpmHandle,
) -> Result<Vec<u8>> {
    let maxsize = context
        .get_tpm_property(PropertyTag::NvBufferMax)?
        .unwrap_or(512) as usize;

    let nv_idx = TpmHandle::NvIndex(nv_index_handle);
    let nv_idx = context.execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_idx))?;
    let nv_idx: NvIndexHandle = nv_idx.into();

    let (nvpub, _) = context.execute_without_session(|ctx| ctx.nv_read_public(nv_idx))?;
    let nvsize = nvpub.data_size();

    let mut result = Vec::new();
    result.reserve_exact(nvsize);

    for offset in (0..nvsize).step_by(maxsize) {
        let size: u16 = std::cmp::min(maxsize, nvsize - offset) as u16;

        let res = context.nv_read(auth_handle, nv_idx, size, offset as u16)?;
        result.extend_from_slice(&res);
    }
    context.execute_without_session(|ctx| ctx.tr_close(&mut nv_idx.into()))?;

    Ok(result)
}

/// Returns the NvPublic and Name associated with an NV index TPM handle
fn get_nv_index_info(
    context: &mut Context,
    nv_index_tpm_handle: NvIndexTpmHandle,
) -> Result<(NvPublic, Name)> {
    context
        .tr_from_tpm_public(nv_index_tpm_handle.into())
        .and_then(|mut object_handle| {
            context
                .nv_read_public(NvIndexHandle::from(object_handle))
                .map_err(|e| {
                    let _ = context.tr_close(&mut object_handle);
                    e
                })
                .and_then(|(nv_public, name)| {
                    context.tr_close(&mut object_handle)?;
                    Ok((nv_public, name))
                })
        })
}

/// Lists all the currently defined NV Indexes' names and public components
pub fn list(context: &mut Context) -> Result<Vec<(NvPublic, Name)>> {
    context.execute_without_session(|ctx| {
        ctx.get_capability(
            CapabilityType::Handles,
            TPM2_NV_INDEX_FIRST,
            TPM2_PT_NV_INDEX_MAX,
        )
        .and_then(|(capability_data, _)| match capability_data {
            CapabilityData::Handles(tpm_handles) => Ok(tpm_handles),
            _ => Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
        })
        .and_then(|tpm_handles| {
            tpm_handles
                .iter()
                .map(|&tpm_handle| get_nv_index_info(ctx, NvIndexTpmHandle::try_from(tpm_handle)?))
                .collect()
        })
    })
}
