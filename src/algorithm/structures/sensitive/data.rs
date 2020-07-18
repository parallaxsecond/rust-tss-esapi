// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPM2B_SENSITIVE_DATA;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;
/// Rust native representation of sensitive data.
///
/// The structure contains the sensitive data as a byte vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SensitiveData {
    value: Vec<u8>,
}

impl SensitiveData {
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl Default for SensitiveData {
    fn default() -> Self {
        SensitiveData {
            value: Vec::<u8>::new(),
        }
    }
}

impl TryFrom<Vec<u8>> for SensitiveData {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > 256 {
            error!("Error: Invalid Vec<u8>size(> {})", 256);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(SensitiveData { value: bytes })
    }
}

impl TryFrom<TPM2B_SENSITIVE_DATA> for SensitiveData {
    type Error = Error;
    fn try_from(tss_sensitive_data: TPM2B_SENSITIVE_DATA) -> Result<Self> {
        let size = tss_sensitive_data.size as usize;
        if size > 256 {
            error!("Error: Invalid TPM2B_SENSITIVE_DATA size(> {})", 256);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(SensitiveData {
            value: tss_sensitive_data.buffer[..size].to_vec(),
        })
    }
}

impl TryFrom<SensitiveData> for TPM2B_SENSITIVE_DATA {
    type Error = Error;
    fn try_from(sensitive_data: SensitiveData) -> Result<Self> {
        if sensitive_data.value().len() > 256 {
            error!("Error: Invalid SensitiveData size(> {})", 256);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut tss_sensitive_data: TPM2B_SENSITIVE_DATA = Default::default();
        if !sensitive_data.value.is_empty() {
            tss_sensitive_data.size = sensitive_data.value().len() as u16;
            tss_sensitive_data.buffer[..sensitive_data.value().len()]
                .copy_from_slice(&sensitive_data.value());
        }
        Ok(tss_sensitive_data)
    }
}
