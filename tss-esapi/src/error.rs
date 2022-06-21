// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod return_code;
mod wrapper;

pub use return_code::{
    ArgumentNumber, BaseReturnCode, EsapiReturnCode, FapiReturnCode, MuapiReturnCode, ReturnCode,
    SapiReturnCode, TctiReturnCode, TpmFormatOneResponseCode, TpmFormatZeroErrorResponseCode,
    TpmFormatZeroResponseCode, TpmFormatZeroWarningResponseCode, TpmResponseCode,
};
pub use wrapper::WrapperErrorKind;

pub type Result<T> = std::result::Result<T, Error>;

/// Main error type used by the crate to return issues with a method call. The value can either be
/// a TSS-generated response code or a wrapper error - marking an issue caught within the wrapping
/// layer.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    WrapperError(WrapperErrorKind),
    TssError(ReturnCode),
}

impl Error {
    /// Creates a wrapper error.
    pub(crate) const fn local_error(kind: WrapperErrorKind) -> Self {
        Error::WrapperError(kind)
    }

    /// Creates a TSS error.
    pub(crate) const fn tss_error(return_code: ReturnCode) -> Self {
        Error::TssError(return_code)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrapperError(e) => e.fmt(f),
            Error::TssError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::WrapperError(wrapper_error) => Some(wrapper_error),
            Error::TssError(response_code) => Some(response_code),
        }
    }
}
