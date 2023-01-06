// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::SensitiveCreate,
    traits::{Marshall, UnMarshall},
    tss2_esys::{TPM2B_SENSITIVE_CREATE, TPMS_SENSITIVE_CREATE},
    Error, Result, ReturnCode, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    ops::Deref,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The [SensitiveCreate] buffer type.
///
/// # Details
/// The SensitiveCreateBuffer contains [SensitiveCreate] in marshalled
/// form. It can be unmarshalled into [SensitiveCreate] or [TPM2B_SENSITIVE_CREATE].
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveCreateBuffer(Vec<u8>);

impl SensitiveCreateBuffer {
    pub const MAX_SIZE: usize = std::mem::size_of::<TPMS_SENSITIVE_CREATE>();
    pub const MIN_SIZE: usize = 4;

    /// Returns the content of the buffer.
    pub fn value(&self) -> &[u8] {
        &self.0
    }

    /// Private function for ensuring that a buffer size is valid.
    fn ensure_valid_buffer_size(buffer_size: usize, container_name: &str) -> Result<()> {
        if (Self::MIN_SIZE..=Self::MAX_SIZE).contains(&buffer_size) {
            Ok(())
        } else {
            error!(
                "Error: Invalid {} size ({} >= {} >= {})",
                container_name,
                Self::MAX_SIZE,
                buffer_size,
                Self::MIN_SIZE,
            );
            Err(Error::local_error(WrapperErrorKind::WrongParamSize))
        }
    }
}

impl Deref for SensitiveCreateBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for SensitiveCreateBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "Vec<u8>")?;
        Ok(SensitiveCreateBuffer(bytes))
    }
}

impl TryFrom<&[u8]> for SensitiveCreateBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "&[u8]")?;
        Ok(SensitiveCreateBuffer(bytes.to_vec()))
    }
}

impl TryFrom<TPM2B_SENSITIVE_CREATE> for SensitiveCreateBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_SENSITIVE_CREATE) -> Result<Self> {
        Self::ensure_valid_buffer_size(tss.size as usize, "buffer")?;
        SensitiveCreate::try_from(tss.sensitive)
            .and_then(|sensitive_create| sensitive_create.marshall())
            .map(SensitiveCreateBuffer)
    }
}

impl TryFrom<SensitiveCreateBuffer> for TPM2B_SENSITIVE_CREATE {
    type Error = Error;

    fn try_from(native: SensitiveCreateBuffer) -> Result<Self> {
        SensitiveCreate::unmarshall(&native.0).map(|sensitive_create| TPM2B_SENSITIVE_CREATE {
            size: native.0.len() as u16,
            sensitive: sensitive_create.into(),
        })
    }
}

impl TryFrom<SensitiveCreateBuffer> for SensitiveCreate {
    type Error = Error;

    fn try_from(buf: SensitiveCreateBuffer) -> Result<Self> {
        SensitiveCreate::unmarshall(&buf.0)
    }
}

impl TryFrom<SensitiveCreate> for SensitiveCreateBuffer {
    type Error = Error;

    fn try_from(sensitve_create: SensitiveCreate) -> Result<SensitiveCreateBuffer> {
        Ok(SensitiveCreateBuffer(sensitve_create.marshall()?))
    }
}

impl Marshall for SensitiveCreateBuffer {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPM2B_SENSITIVE_CREATE>();

    /// Produce a marshalled [TPM2B_SENSITIVE_CREATE]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_SENSITIVE_CREATE_Marshal(
                    &self.clone().try_into()?,
                    buffer.as_mut_ptr(),
                    Self::BUFFER_SIZE.try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                )
            },
            |ret| {
                error!("Failed to marshal SensitiveCreateBuffer: {}", ret);
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

impl UnMarshall for SensitiveCreateBuffer {
    /// Unmarshall the structure from [TPM2B_SENSITIVE_CREATE]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        let mut dest = TPM2B_SENSITIVE_CREATE::default();
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2B_SENSITIVE_CREATE_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal SensitiveCreateBuffer: {}", ret),
        )?;

        SensitiveCreateBuffer::try_from(dest)
    }
}
