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

use crate::constants::response_code::Tss2ResponseCode;
use crate::tss2_esys::TSS2_RC;

/// Main error type used by the crate to return issues with a method call. The value can either be
/// a TSS-generated response code or a wrapper error - marking an issue caught within the wrapping
/// layer.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Error {
    WrapperError(WrapperErrorKind),
    Tss2Error(Tss2ResponseCode),
}

impl Error {
    pub(crate) fn from_tss_rc(rc: TSS2_RC) -> Self {
        Error::Tss2Error(Tss2ResponseCode::from_tss_rc(rc))
    }

    pub(crate) fn local_error(kind: WrapperErrorKind) -> Self {
        Error::WrapperError(kind)
    }

    /// Verify whether the value contained is a success response code.
    pub fn is_success(self) -> bool {
        if let Error::Tss2Error(tss2_rc) = self {
            tss2_rc.is_success()
        } else {
            false
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::WrapperError(e) => e.fmt(f),
            Error::Tss2Error(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::WrapperError(wrapper_error) => Some(wrapper_error),
            Error::Tss2Error(response_code) => Some(response_code),
        }
    }
}
