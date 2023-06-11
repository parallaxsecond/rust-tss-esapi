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

    /// Writes the type in the form of marshalled data to `marshalled_data`,
    /// and modifies the `offset` to point to the first byte in the buffer
    /// which was not written in the conversion.
    fn marshall_offset(
        &self,
        _marshalled_data: &mut [u8],
        _offset: &mut std::os::raw::c_ulong,
    ) -> Result<()> {
        unimplemented!();
    }
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

        self.marshall_offset(&mut buffer, &mut offset)?;

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }

    fn marshall_offset(
        &self,
        marshalled_data: &mut [u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_UINT32_Marshal(
                    *self,
                    marshalled_data.as_mut_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                )
            },
            |ret| {
                error!("Failed to marshall u32: {}", ret);
            },
        )?;

        Ok(())
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
