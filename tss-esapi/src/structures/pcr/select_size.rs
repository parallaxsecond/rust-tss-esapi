// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{Error, Result, WrapperErrorKind};

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};

use log::error;
use std::convert::TryFrom;

/// Enum with the possible values for sizeofSelect.
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PcrSelectSize {
    OneByte = 1,
    TwoBytes = 2,
    ThreeBytes = 3,
    FourBytes = 4,
}

/// The default for PcrSelectSize is three bytes.
/// A value for the sizeofSelect that works
/// on most platforms.
impl Default for PcrSelectSize {
    fn default() -> PcrSelectSize {
        PcrSelectSize::ThreeBytes
    }
}

impl TryFrom<u8> for PcrSelectSize {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        PcrSelectSize::from_u8(value).ok_or_else(|| {
            error!(
                "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<PcrSelectSize> for u8 {
    fn from(pcr_select_size: PcrSelectSize) -> Self {
        // The value is well defined so unwrap will
        // never cause panic.
        pcr_select_size.to_u8().unwrap()
    }
}

impl From<PcrSelectSize> for usize {
    fn from(pcr_select_size: PcrSelectSize) -> Self {
        // The value is well defined so unwrap will
        // never cause panic.
        pcr_select_size.to_usize().unwrap()
    }
}
