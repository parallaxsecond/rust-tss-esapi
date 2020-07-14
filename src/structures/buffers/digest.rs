// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2B_DIGEST;
use log::error;
use std::convert::TryFrom;
use std::ops::Deref;
/// Struct holding a pcr value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digest {
    value: Vec<u8>,
}

impl Deref for Digest {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl Digest {
    const MAX_SIZE: usize = 64;
    /// Function for retrieving the value.
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for Digest {
    fn default() -> Self {
        Digest {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for Digest {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Digest::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", Digest::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Digest { value: bytes })
    }
}

impl TryFrom<TPM2B_DIGEST> for Digest {
    type Error = Error;
    fn try_from(tss_digest: TPM2B_DIGEST) -> Result<Self> {
        let size = tss_digest.size as usize;
        if size > Digest::MAX_SIZE {
            error!("Error: Invalid TPM2B_DIGEST size(> {})", Digest::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(Digest {
            value: tss_digest.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<Digest> for TPM2B_DIGEST {
    type Error = Error;
    fn try_from(digest: Digest) -> Result<Self> {
        let size = digest.len();
        if size > Digest::MAX_SIZE {
            error!("Error: Invalid Digest size(> {})", Digest::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_digest: TPM2B_DIGEST = Default::default();
        if !digest.value.is_empty() {
            tss_digest.size = size as u16;
            tss_digest.buffer[..size].copy_from_slice(digest.value());
        }
        Ok(tss_digest)
    }
}
