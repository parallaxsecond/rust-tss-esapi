// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::return_code::BaseError, Error, Result};
use std::convert::TryFrom;

/// Struct representing the TSS base response code
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct BaseReturnCode {
    base_error: BaseError,
}

impl BaseReturnCode {
    /// Returns the [BaseError] associated with the base return code.
    pub const fn base_error(&self) -> BaseError {
        self.base_error
    }
}

impl From<BaseError> for BaseReturnCode {
    fn from(base_error: BaseError) -> Self {
        BaseReturnCode { base_error }
    }
}

impl From<BaseReturnCode> for BaseError {
    fn from(base_response_code: BaseReturnCode) -> Self {
        base_response_code.base_error
    }
}

impl TryFrom<u16> for BaseReturnCode {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self> {
        BaseError::try_from(value).map(BaseReturnCode::from)
    }
}

impl From<BaseReturnCode> for u16 {
    fn from(base_response_code: BaseReturnCode) -> Self {
        BaseError::from(base_response_code).into()
    }
}

impl std::error::Error for BaseReturnCode {}

impl std::fmt::Display for BaseReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.base_error {
            BaseError::GeneralFailure => write!(f, "General Error"),
            BaseError::NotImplemented => write!(f, "Not Implemented"),
            BaseError::BadContext => write!(f, "Bad Context"),
            BaseError::AbiMismatch => write!(f, "ABI Mismatch"),
            BaseError::BadReference => write!(f, "Bad Reference"),
            BaseError::InsufficientBuffer => write!(f, "Insufficient Buffer"),
            BaseError::BadSequence => write!(f, "Bad Sequence"),
            BaseError::NoConnection => write!(f, "No Connection"),
            BaseError::TryAgain => write!(f, "Try Again"),
            BaseError::IoError => write!(f, "IO Error"),
            BaseError::BadValue => write!(f, "Bad Value"),
            BaseError::NotPermitted => write!(f, "Not Permitted"),
            BaseError::InvalidSessions => write!(f, "Invalid Sessions"),
            BaseError::NoDecryptParam => write!(f, "No Decrypt Param"),
            BaseError::NoEncryptParam => write!(f, "No Encrypt Param"),
            BaseError::BadSize => write!(f, "Bad Size"),
            BaseError::MalformedResponse => write!(f, "Malformed Response"),
            BaseError::InsufficientContext => write!(f, "Insufficient Context"),
            BaseError::InsufficientResponse => write!(f, "Insufficient Response"),
            BaseError::IncompatibleTcti => write!(f, "Incompatible TCTI"),
            BaseError::NotSupported => write!(f, "Not Supported"),
            BaseError::BadTctiStructure => write!(f, "Bad TCTI Structure"),
            BaseError::Memory => write!(f, "Memory"),
            BaseError::BadTr => write!(f, "Bad TR"),
            BaseError::MultipleDecryptSessions => write!(f, "Multiple Decrypt Sessions"),
            BaseError::MultipleEncryptSessions => write!(f, "Multiple Encrypt Sessions"),
            BaseError::RspAuthFailed => write!(f, "RSP Auth Failed"),
            BaseError::NoConfig => write!(f, "No Config"),
            BaseError::BadPath => write!(f, "Bad Path"),
            BaseError::NotDeletable => write!(f, "Not Deletable"),
            BaseError::PathAlreadyExists => write!(f, "Path Already Exists"),
            BaseError::KeyNotFound => write!(f, "Key Not Found"),
            BaseError::SignatureVerificationFailed => write!(f, "Signature Verification Failed"),
            BaseError::HashMismatch => write!(f, "Hash Mismatch"),
            BaseError::KeyNotDuplicable => write!(f, "Key Not Duplicable"),
            BaseError::PathNotFound => write!(f, "Path Not Found"),
            BaseError::NoCert => write!(f, "No Cert"),
            BaseError::NoPcr => write!(f, "No PCR"),
            BaseError::PcrNotResettable => write!(f, "PCR Not Resettable"),
            BaseError::BadTemplate => write!(f, "Bad Template"),
            BaseError::AuthorizationFailed => write!(f, "Authorization Failed"),
            BaseError::AuthorizationUnknown => write!(f, "Authorization Unknown"),
            BaseError::NvNotReadable => write!(f, "NV Not Readable"),
            BaseError::NvTooSmall => write!(f, "NV Too Small"),
            BaseError::NvNotWriteable => write!(f, "NV Not Writeable"),
            BaseError::PolicyUnknown => write!(f, "Policy Unknown"),
            BaseError::NvWrongType => write!(f, "NV Wrong Type"),
            BaseError::NameAlreadyExists => write!(f, "Name Already Exists"),
            BaseError::NoTpm => write!(f, "No TPM"),
            BaseError::BadKey => write!(f, "Bad Key"),
            BaseError::NoHandle => write!(f, "No Handle"),
            BaseError::NotProvisioned => write!(f, "Not Provisioned"),
            BaseError::AlreadyProvisioned => write!(f, "Already Provisioned"),
        }
    }
}
