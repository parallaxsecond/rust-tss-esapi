// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPM2B_PUBLIC_KEY_RSA;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Struct holding the largest RSA public key supported by the TPM
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PublicKeyRSA {
    value: Vec<u8>,
}

impl PublicKeyRSA {
    const MAX_SIZE: usize = 512;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl TryFrom<Vec<u8>> for PublicKeyRSA {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > PublicKeyRSA::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", PublicKeyRSA::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(PublicKeyRSA { value: bytes })
    }
}

impl TryFrom<TPM2B_PUBLIC_KEY_RSA> for PublicKeyRSA {
    type Error = Error;
    fn try_from(tss_data: TPM2B_PUBLIC_KEY_RSA) -> Result<Self> {
        let size = tss_data.size as usize;
        if size > PublicKeyRSA::MAX_SIZE {
            error!(
                "Error: Invalid TPM2B_PUBLIC_KEY_RSA size(> {})",
                PublicKeyRSA::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(PublicKeyRSA {
            value: tss_data.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<PublicKeyRSA> for TPM2B_PUBLIC_KEY_RSA {
    type Error = Error;
    fn try_from(data: PublicKeyRSA) -> Result<Self> {
        if data.value().len() > PublicKeyRSA::MAX_SIZE {
            error!(
                "Error: Invalid data size(> {}) in PublicKeyRSA",
                PublicKeyRSA::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_data: TPM2B_PUBLIC_KEY_RSA = Default::default();
        if !data.value.is_empty() {
            tss_data.size = data.value().len() as u16;
            tss_data.buffer[..data.value().len()].copy_from_slice(&data.value());
        }
        Ok(tss_data)
    }
}
