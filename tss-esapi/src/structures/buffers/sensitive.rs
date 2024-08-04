// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::Sensitive,
    traits::{impl_mu_complex, Marshall, UnMarshall},
    tss2_esys::{TPM2B_SENSITIVE, TPMT_SENSITIVE},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    ops::Deref,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sensitive data buffer.
///
/// # Details
/// Corresponds to `TPM2B_SENSITIVE`. The contents of
/// the buffer can be unmarshalled into a [Sensitive]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SensitiveBuffer(Vec<u8>);

impl SensitiveBuffer {
    #[allow(unused_qualifications)]
    pub const MAX_SIZE: usize = std::mem::size_of::<TPMT_SENSITIVE>();

    pub fn value(&self) -> &[u8] {
        &self.0
    }

    /// Private function for ensuring that a buffer size is valid.
    fn ensure_valid_buffer_size(buffer_size: usize, container_name: &str) -> Result<()> {
        if buffer_size > Self::MAX_SIZE {
            error!("Invalid {} size(> {})", container_name, Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(())
    }
}

impl Deref for SensitiveBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for SensitiveBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "Vec<u8>")?;
        Ok(SensitiveBuffer(bytes))
    }
}

impl TryFrom<&[u8]> for SensitiveBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "&[u8]")?;
        Ok(SensitiveBuffer(bytes.to_vec()))
    }
}

impl TryFrom<TPM2B_SENSITIVE> for SensitiveBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_SENSITIVE) -> Result<Self> {
        let size = tss.size as usize;
        Self::ensure_valid_buffer_size(size, "buffer")?;
        Sensitive::try_from(tss.sensitiveArea)
            .and_then(|sensitive| sensitive.marshall())
            .map(SensitiveBuffer)
    }
}

impl TryFrom<SensitiveBuffer> for TPM2B_SENSITIVE {
    type Error = Error;

    fn try_from(native: SensitiveBuffer) -> Result<Self> {
        let mut buffer = TPM2B_SENSITIVE {
            size: native.0.len() as u16,
            ..Default::default()
        };
        let sensitive = Sensitive::unmarshall(&native.0)?;
        buffer.sensitiveArea = sensitive.into();
        Ok(buffer)
    }
}

impl TryFrom<SensitiveBuffer> for Sensitive {
    type Error = Error;

    fn try_from(buf: SensitiveBuffer) -> Result<Self> {
        Sensitive::unmarshall(&buf.0)
    }
}

impl TryFrom<Sensitive> for SensitiveBuffer {
    type Error = Error;

    fn try_from(sensitive: Sensitive) -> Result<SensitiveBuffer> {
        Ok(SensitiveBuffer(sensitive.marshall()?))
    }
}

impl_mu_complex!(SensitiveBuffer, TPM2B_SENSITIVE);
