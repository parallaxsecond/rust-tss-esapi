// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::{TPM2B_MAX_BUFFER, TPM2_MAX_DIGEST_BUFFER};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Struct holding a max buffer value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxBuffer {
    value: Vec<u8>,
}

impl MaxBuffer {
    const MAX_SIZE: usize = TPM2_MAX_DIGEST_BUFFER as usize;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for MaxBuffer {
    fn default() -> Self {
        MaxBuffer {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for MaxBuffer {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MaxBuffer::MAX_SIZE {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(MaxBuffer { value: bytes })
    }
}

impl TryFrom<TPM2B_MAX_BUFFER> for MaxBuffer {
    type Error = Error;
    fn try_from(tss_max_buffer: TPM2B_MAX_BUFFER) -> Result<Self> {
        let size = tss_max_buffer.size as usize;
        if size > MaxBuffer::MAX_SIZE {
            error!(
                "Error: Invalid TPM2B_MAX_BUFFER size(> {})",
                MaxBuffer::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(MaxBuffer {
            value: tss_max_buffer.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<MaxBuffer> for TPM2B_MAX_BUFFER {
    type Error = Error;
    fn try_from(max_buffer: MaxBuffer) -> Result<Self> {
        if max_buffer.value.len() > MaxBuffer::MAX_SIZE {
            error!("Error: Invalid MaxBuffer size(> {})", MaxBuffer::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_max_buffer: TPM2B_MAX_BUFFER = Default::default();
        if !max_buffer.value.is_empty() {
            tss_max_buffer.size = max_buffer.value().len() as u16;
            tss_max_buffer.buffer[..max_buffer.value().len()].copy_from_slice(&max_buffer.value());
        }
        Ok(tss_max_buffer)
    }
}
