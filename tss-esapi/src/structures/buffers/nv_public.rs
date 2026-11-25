// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Error, Result, WrapperErrorKind,
    structures::NvPublic,
    traits::{Marshall, UnMarshall, impl_mu_complex},
    tss2_esys::{TPM2B_NV_PUBLIC, TPMS_NV_PUBLIC},
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    ops::Deref,
};

/// NvPublic data buffer.
///
/// # Details
/// Corresponds to `TPM2B_NV_PUBLIC`. The contents of
/// the buffer can be unmarshalled into an [NvPublic]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvPublicBuffer(Vec<u8>);

impl NvPublicBuffer {
    pub const MAX_SIZE: usize = size_of::<TPMS_NV_PUBLIC>();

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

impl Deref for NvPublicBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for NvPublicBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "Vec<u8>")?;
        Ok(NvPublicBuffer(bytes))
    }
}

impl TryFrom<&[u8]> for NvPublicBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "&[u8]")?;
        Ok(NvPublicBuffer(bytes.to_vec()))
    }
}

impl TryFrom<TPM2B_NV_PUBLIC> for NvPublicBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_NV_PUBLIC) -> Result<Self> {
        let size = tss.size as usize;
        Self::ensure_valid_buffer_size(size, "buffer")?;
        NvPublic::try_from(tss.nvPublic)
            .and_then(|nv_public| nv_public.marshall())
            .map(NvPublicBuffer)
    }
}

impl TryFrom<NvPublicBuffer> for TPM2B_NV_PUBLIC {
    type Error = Error;

    fn try_from(native: NvPublicBuffer) -> Result<Self> {
        let nv_public = NvPublic::unmarshall(&native.0)?;
        Ok(TPM2B_NV_PUBLIC {
            size: native.0.len() as u16,
            nvPublic: nv_public.try_into()?,
        })
    }
}

impl TryFrom<NvPublicBuffer> for NvPublic {
    type Error = Error;

    fn try_from(buf: NvPublicBuffer) -> Result<Self> {
        NvPublic::unmarshall(&buf.0)
    }
}

impl TryFrom<NvPublic> for NvPublicBuffer {
    type Error = Error;

    fn try_from(nv_public: NvPublic) -> Result<NvPublicBuffer> {
        Ok(NvPublicBuffer(nv_public.marshall()?))
    }
}

impl_mu_complex!(NvPublicBuffer, TPM2B_NV_PUBLIC);
