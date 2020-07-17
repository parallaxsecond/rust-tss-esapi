// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2B_NAME;
use log::error;
use std::convert::TryFrom;
/// Structure holding the data representing names
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Name {
    value: Vec<u8>,
}

impl Name {
    const MAX_SIZE: usize = 68;
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl TryFrom<Vec<u8>> for Name {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Name::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", Name::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(Name { value: bytes })
    }
}

impl TryFrom<TPM2B_NAME> for Name {
    type Error = Error;
    fn try_from(tss_name: TPM2B_NAME) -> Result<Self> {
        let size = tss_name.size as usize;
        if size > Name::MAX_SIZE {
            error!("Error: Invalid TPM2B_NAME size(> {})", Name::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(Name {
            value: tss_name.name[..size].to_vec(),
        })
    }
}

impl TryFrom<Name> for TPM2B_NAME {
    type Error = Error;
    fn try_from(name: Name) -> Result<TPM2B_NAME> {
        let size = name.value.len();
        if size > Name::MAX_SIZE {
            error!("Error: Invalid Name size(> {})", Name::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_name: TPM2B_NAME = Default::default();
        tss_name.size = size as u16;
        tss_name.name[..size].copy_from_slice(&name.value());
        Ok(tss_name)
    }
}
