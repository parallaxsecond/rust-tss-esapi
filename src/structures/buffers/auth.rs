// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2B_AUTH;
use log::error;
use std::convert::TryFrom;
/// Struct holding a auth value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    value: Vec<u8>,
}

impl Auth {
    const MAX_SIZE: usize = 64;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for Auth {
    fn default() -> Self {
        Auth {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for Auth {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Auth::MAX_SIZE {
            error!("Error: Invalid vector size size(> {})", Auth::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Auth { value: bytes })
    }
}

impl TryFrom<TPM2B_AUTH> for Auth {
    type Error = Error;
    fn try_from(tss_auth: TPM2B_AUTH) -> Result<Self> {
        let size = tss_auth.size as usize;
        if size > Auth::MAX_SIZE {
            error!("Error: Invalid TPM2B_AUTH size(> {})", Auth::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Auth {
            value: tss_auth.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<Auth> for TPM2B_AUTH {
    type Error = Error;
    fn try_from(auth: Auth) -> Result<Self> {
        if auth.value().len() > Auth::MAX_SIZE {
            error!("Error: Invalid data size(> {}) in Auth", Auth::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_auth: TPM2B_AUTH = Default::default();
        if !auth.value.is_empty() {
            tss_auth.size = auth.value().len() as u16;
            tss_auth.buffer[..auth.value().len()].copy_from_slice(&auth.value());
        }
        Ok(tss_auth)
    }
}
