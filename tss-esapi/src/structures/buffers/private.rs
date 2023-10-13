// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    traits::{Marshall, UnMarshall},
    ReturnCode,
};
use std::convert::TryInto;
use tss_esapi_sys::_PRIVATE;

buffer_type!(Private, ::std::mem::size_of::<_PRIVATE>(), TPM2B_PRIVATE);

impl Marshall for Private {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPM2B_PRIVATE>();

    /// Produce a marshalled [`TPM2B_PRIVATE`]
    fn marshall_offset(
        &self,
        marshalled_data: &mut [u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Marshal(
                    &self.clone().try_into().map_err(|e| {
                        error!("Failed to convert Private to TPM2B_PRIVATE: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    marshalled_data.as_mut_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                )
            },
            |ret| {
                error!("Failed to marshal Private: {}", ret);
            },
        )?;

        Ok(())
    }
}

impl UnMarshall for Private {
    /// Unmarshall the structure from [`TPM2B_PRIVATE`]
    fn unmarshall_offset(
        marshalled_data: &[u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<Self> {
        let mut dest = TPM2B_PRIVATE::default();
        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_PRIVATE_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal Private: {}", ret),
        )?;
        Private::try_from(dest)
    }
}
