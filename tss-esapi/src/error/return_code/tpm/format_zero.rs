// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod error;
mod warning;

use crate::{Error, Result, WrapperErrorKind};
use bitfield::bitfield;
pub use error::TpmFormatZeroErrorResponseCode;
use log::error;
use std::convert::TryFrom;
pub use warning::TpmFormatZeroWarningResponseCode;

/// Enum representing the TPM format zero response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TpmFormatZeroResponseCode {
    Error(TpmFormatZeroErrorResponseCode),
    Warning(TpmFormatZeroWarningResponseCode),
    VendorSpecific(u16),
}

impl TryFrom<u16> for TpmFormatZeroResponseCode {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        let structure = FormatZeroResponseCodeStructure(value);
        if structure.reserved() {
            error!("Found non zero reserved bit in TPM format zero response code");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        if structure.is_tpm_2_0() {
            if structure.is_vendor_specific() {
                Ok(TpmFormatZeroResponseCode::VendorSpecific(value))
            } else if structure.is_warning() {
                TpmFormatZeroWarningResponseCode::try_from(structure.error_number())
                    .map(TpmFormatZeroResponseCode::Warning)
            } else {
                TpmFormatZeroErrorResponseCode::try_from(structure.error_number())
                    .map(TpmFormatZeroResponseCode::Error)
            }
        } else {
            error!("Found a TPM 1.2 format zero response code, these are not supported.");
            Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
        }
    }
}

impl From<TpmFormatZeroResponseCode> for u16 {
    fn from(tpm_format_zero_response_code: TpmFormatZeroResponseCode) -> u16 {
        match tpm_format_zero_response_code {
            TpmFormatZeroResponseCode::Error(error) => {
                let mut structure = FormatZeroResponseCodeStructure(0);
                structure.set_is_vendor_specific(false);
                structure.set_is_warning(false);
                structure.set_reserved(false);
                structure.set_tpm_2_0(true);
                structure.set_error_number(error.into());
                structure.0
            }
            TpmFormatZeroResponseCode::Warning(warning) => {
                let mut structure = FormatZeroResponseCodeStructure(0);
                structure.set_is_vendor_specific(false);
                structure.set_is_warning(true);
                structure.set_reserved(false);
                structure.set_tpm_2_0(true);
                structure.set_error_number(warning.into());
                structure.0
            }
            TpmFormatZeroResponseCode::VendorSpecific(value) => value,
        }
    }
}

impl std::error::Error for TpmFormatZeroResponseCode {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TpmFormatZeroResponseCode::Error(error) => Some(error),
            TpmFormatZeroResponseCode::Warning(warning) => Some(warning),
            TpmFormatZeroResponseCode::VendorSpecific(_) => None,
        }
    }
}

impl std::fmt::Display for TpmFormatZeroResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmFormatZeroResponseCode::Error(e) => e.fmt(f),
            TpmFormatZeroResponseCode::Warning(e) => e.fmt(f),
            TpmFormatZeroResponseCode::VendorSpecific(_) => write!(f, "Vendor specific error"),
        }
    }
}

bitfield! {
    #[derive(Copy, Clone, PartialEq, Eq)]
    pub struct FormatZeroResponseCodeStructure(u16);
    impl Debug;
    u8, error_number, set_error_number: 6, 0;
    is_tpm_2_0, set_tpm_2_0: 8;
    reserved, set_reserved: 9; // Shall be zero
    is_vendor_specific, set_is_vendor_specific: 10;
    is_warning, set_is_warning: 11;
}
