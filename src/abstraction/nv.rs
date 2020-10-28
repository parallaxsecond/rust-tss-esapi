// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tags::PropertyTag,
    handles::{AuthHandle, NvIndexHandle, NvIndexTpmHandle, TpmHandle},
    Context, Result,
};

/// Allows reading an NV Index completely, regardless of the max TPM NV buffer size
pub fn read_full(
    context: &mut Context,
    auth_handle: AuthHandle,
    nv_index_handle: NvIndexTpmHandle,
) -> Result<Vec<u8>> {
    let maxsize = match context.get_tpm_property(PropertyTag::NvBufferMax)? {
        Some(val) => val,
        None => 512,
    } as usize;

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

    Ok(result)
}
