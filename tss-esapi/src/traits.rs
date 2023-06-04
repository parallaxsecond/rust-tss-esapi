use std::convert::{TryFrom, TryInto};

use log::error;
use tss_esapi_sys::UINT32;

// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{Error, Result, ReturnCode, WrapperErrorKind};

/// Trait for types that can be converted into
/// TPM marshalled data.
pub trait Marshall: Sized {
    const BUFFER_SIZE: usize;
    /// Returns the type in the form of marshalled data
    fn marshall(&self) -> Result<Vec<u8>>;
}

/// Trait for types that can be created from
/// TPM marshalled data.
pub trait UnMarshall: Sized {
    /// Creates the type from marshalled data.
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self>;

    /// Creates the type from the marshalled data, and modifies
    /// the `offset` to point to the first byte in the `marshalled_data`
    /// buffer which was not used in the conversion.
    fn unmarshall_offset(
        _marshalled_data: &[u8],
        _offset: &mut std::os::raw::c_ulong,
    ) -> Result<Self> {
        unimplemented!();
    }
}

impl Marshall for u32 {
    const BUFFER_SIZE: usize = std::mem::size_of::<UINT32>();

    /// Produce a marshalled [UINT32]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_UINT32_Marshal(
                    *self,
                    buffer.as_mut_ptr(),
                    Self::BUFFER_SIZE.try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                )
            },
            |ret| {
                error!("Failed to marshall u32: {}", ret);
            },
        )?;

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for u32 {
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        u32::unmarshall_offset(marshalled_data, &mut 0)
    }

    fn unmarshall_offset(
        marshalled_data: &[u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<Self> {
        let mut dest = 0_u32;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_UINT32_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal SensitiveCreate: {}", ret),
        )?;

        Ok(dest)
    }
}
