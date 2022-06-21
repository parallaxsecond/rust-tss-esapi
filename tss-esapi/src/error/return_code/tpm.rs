// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod format_one;
mod format_zero;

use crate::{Error, Result};
use bitfield::bitfield;
pub use format_one::{ArgumentNumber, TpmFormatOneResponseCode};
pub use format_zero::{
    TpmFormatZeroErrorResponseCode, TpmFormatZeroResponseCode, TpmFormatZeroWarningResponseCode,
};
use std::convert::TryFrom;

/// Enum representing an TPM response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum TpmResponseCode {
    FormatZero(TpmFormatZeroResponseCode),
    FormatOne(TpmFormatOneResponseCode),
}

impl TryFrom<u16> for TpmResponseCode {
    type Error = Error;
    fn try_from(value: u16) -> Result<Self> {
        if FormatSelector(value).is_format_one() {
            TpmFormatOneResponseCode::try_from(value).map(TpmResponseCode::FormatOne)
        } else {
            TpmFormatZeroResponseCode::try_from(value).map(TpmResponseCode::FormatZero)
        }
    }
}

impl From<TpmResponseCode> for u16 {
    fn from(tpm_response_code: TpmResponseCode) -> u16 {
        match tpm_response_code {
            TpmResponseCode::FormatOne(rc) => {
                let mut format_selector = FormatSelector(rc.into());
                format_selector.set_format_one(true);
                format_selector.0
            }
            TpmResponseCode::FormatZero(rc) => {
                let mut format_selector = FormatSelector(rc.into());
                format_selector.set_format_one(false);
                format_selector.0
            }
        }
    }
}

impl std::error::Error for TpmResponseCode {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TpmResponseCode::FormatOne(rc) => Some(rc),
            TpmResponseCode::FormatZero(rc) => Some(rc),
        }
    }
}

impl std::fmt::Display for TpmResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmResponseCode::FormatOne(e) => e.fmt(f),
            TpmResponseCode::FormatZero(e) => e.fmt(f),
        }
    }
}

bitfield! {
    struct FormatSelector(u16);
    impl Debug;
    is_format_one, set_format_one: 7;
}
