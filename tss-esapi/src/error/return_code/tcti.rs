// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::BaseError, error::return_code::BaseReturnCode, Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::TryFrom;

/// Enum representing the TSS base return code constants.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TctiReturnCode {
    base_error: BaseError,
}

impl TctiReturnCode {
    /// Returns the [BaseError] associated with the TCTI return code.
    pub const fn base_error(&self) -> BaseError {
        self.base_error
    }
}

impl From<TctiReturnCode> for BaseReturnCode {
    fn from(tcti_return_code: TctiReturnCode) -> Self {
        tcti_return_code.base_error.into()
    }
}

impl TryFrom<BaseReturnCode> for TctiReturnCode {
    type Error = Error;

    fn try_from(base_return_code: BaseReturnCode) -> Result<Self> {
        TctiReturnCode::try_from(BaseError::from(base_return_code))
    }
}

impl TryFrom<u16> for TctiReturnCode {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        TctiReturnCode::try_from(BaseError::try_from(value)?)
    }
}

impl From<TctiReturnCode> for u16 {
    fn from(tcti_error_code: TctiReturnCode) -> Self {
        BaseReturnCode::from(tcti_error_code).into()
    }
}

impl TryFrom<BaseError> for TctiReturnCode {
    type Error = Error;

    fn try_from(base_error: BaseError) -> Result<Self> {
        match base_error {
            BaseError::GeneralFailure
            | BaseError::NotImplemented
            | BaseError::BadContext
            | BaseError::AbiMismatch
            | BaseError::BadReference
            | BaseError::InsufficientBuffer
            | BaseError::BadSequence
            | BaseError::NoConnection
            | BaseError::TryAgain
            | BaseError::IoError
            | BaseError::BadValue
            | BaseError::NotPermitted
            | BaseError::MalformedResponse
            | BaseError::NotSupported => Ok(TctiReturnCode { base_error }),
            _ => {
                error!(
                    "{} is not a valid TctiReturnCode base error",
                    u16::from(base_error)
                );
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

impl From<TctiReturnCode> for BaseError {
    fn from(tcti_return_code: TctiReturnCode) -> Self {
        tcti_return_code.base_error
    }
}

impl std::error::Error for TctiReturnCode {}

impl std::fmt::Display for TctiReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", BaseReturnCode::from(*self))
    }
}
