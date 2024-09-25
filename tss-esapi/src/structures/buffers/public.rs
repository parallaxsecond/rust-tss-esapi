// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::Public,
    traits::{impl_mu_complex, Marshall, UnMarshall},
    tss2_esys::{TPM2B_PUBLIC, TPMT_PUBLIC},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::{
    convert::{TryFrom, TryInto},
    mem::size_of,
    ops::Deref,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Public data buffer.
///
/// # Details
/// Corresponds to `TPM2B_PUBLIC`. The contents of
/// the buffer can be unmarshalled into a [Public]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct PublicBuffer(Vec<u8>);

impl PublicBuffer {
    pub const MAX_SIZE: usize = size_of::<TPMT_PUBLIC>();

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

impl Deref for PublicBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for PublicBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "Vec<u8>")?;
        Ok(PublicBuffer(bytes))
    }
}

impl TryFrom<&[u8]> for PublicBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "&[u8]")?;
        Ok(PublicBuffer(bytes.to_vec()))
    }
}

impl TryFrom<TPM2B_PUBLIC> for PublicBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_PUBLIC) -> Result<Self> {
        let size = tss.size as usize;
        Self::ensure_valid_buffer_size(size, "buffer")?;
        Public::try_from(tss.publicArea)
            .and_then(|public| public.marshall())
            .map(PublicBuffer)
    }
}

impl TryFrom<PublicBuffer> for TPM2B_PUBLIC {
    type Error = Error;

    fn try_from(native: PublicBuffer) -> Result<Self> {
        let mut buffer = TPM2B_PUBLIC {
            size: native.0.len() as u16,
            ..Default::default()
        };
        let public = Public::unmarshall(&native.0)?;
        buffer.publicArea = public.into();
        Ok(buffer)
    }
}

impl TryFrom<PublicBuffer> for Public {
    type Error = Error;

    fn try_from(buf: PublicBuffer) -> Result<Self> {
        Public::unmarshall(&buf.0)
    }
}

impl TryFrom<Public> for PublicBuffer {
    type Error = Error;

    fn try_from(public: Public) -> Result<PublicBuffer> {
        Ok(PublicBuffer(public.marshall()?))
    }
}

impl_mu_complex!(PublicBuffer, TPM2B_PUBLIC);
