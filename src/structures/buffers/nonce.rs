// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPM2B_NONCE;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Struct holding a nonce value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    value: Vec<u8>,
}

impl Nonce {
    const MAX_SIZE: usize = 64;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for Nonce {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Nonce::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", Nonce::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Nonce { value: bytes })
    }
}

impl TryFrom<TPM2B_NONCE> for Nonce {
    type Error = Error;
    fn try_from(tss_nonce: TPM2B_NONCE) -> Result<Self> {
        let size = tss_nonce.size as usize;
        if size > Nonce::MAX_SIZE {
            error!("Error: Invalid TPM2B_NONCE size(> {})", Nonce::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Nonce {
            value: tss_nonce.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<Nonce> for TPM2B_NONCE {
    type Error = Error;
    fn try_from(nonce: Nonce) -> Result<Self> {
        if nonce.value.len() > Nonce::MAX_SIZE {
            error!("Error: Invalid data size(> {}) in nonce", Nonce::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_nonce: TPM2B_NONCE = Default::default();
        if !nonce.value.is_empty() {
            tss_nonce.size = nonce.value().len() as u16;
            tss_nonce.buffer[..nonce.value().len()].copy_from_slice(&nonce.value());
        }
        Ok(tss_nonce)
    }
}
