// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::{TPM2B_MAX_NV_BUFFER, TPM2_MAX_NV_BUFFER_SIZE};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Struct holding a max buffer value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxNvBuffer {
    value: Vec<u8>,
}

impl MaxNvBuffer {
    const MAX_SIZE: usize = TPM2_MAX_NV_BUFFER_SIZE as usize;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for MaxNvBuffer {
    fn default() -> Self {
        MaxNvBuffer {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for MaxNvBuffer {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > MaxNvBuffer::MAX_SIZE {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(MaxNvBuffer { value: bytes })
    }
}

impl TryFrom<TPM2B_MAX_NV_BUFFER> for MaxNvBuffer {
    type Error = Error;
    fn try_from(tss_max_nv_buffer: TPM2B_MAX_NV_BUFFER) -> Result<Self> {
        let size = tss_max_nv_buffer.size as usize;
        if size > MaxNvBuffer::MAX_SIZE {
            error!(
                "Error: Invalid TPM2B_MAX_NV_BUFFER size(> {})",
                MaxNvBuffer::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(MaxNvBuffer {
            value: tss_max_nv_buffer.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<MaxNvBuffer> for TPM2B_MAX_NV_BUFFER {
    type Error = Error;
    fn try_from(max_nv_buffer: MaxNvBuffer) -> Result<Self> {
        if max_nv_buffer.value.len() > MaxNvBuffer::MAX_SIZE {
            error!(
                "Error: Invalid MaxNvBuffer size(> {})",
                MaxNvBuffer::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_max_nv_buffer: TPM2B_MAX_NV_BUFFER = Default::default();
        if !max_nv_buffer.value.is_empty() {
            tss_max_nv_buffer.size = max_nv_buffer.value().len() as u16;
            tss_max_nv_buffer.buffer[..max_nv_buffer.value().len()]
                .copy_from_slice(&max_nv_buffer.value());
        }
        Ok(tss_max_nv_buffer)
    }
}
