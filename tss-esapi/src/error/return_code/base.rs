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
            BaseError::GeneralFailure => write!(f, "An unspecified error occurred."),
            BaseError::NotImplemented => write!(f, "Called functionality isn't implemented."),
            BaseError::BadContext => write!(f, "A context structure is bad."),
            BaseError::AbiMismatch => write!(
                f,
                "Passed in ABI version doesn't match called module's ABI version."
            ),
            BaseError::BadReference => {
                write!(f, "A pointer is NULL that isn't allowed to be NULL.")
            }
            BaseError::InsufficientBuffer => write!(f, "A buffer isn't large enough."),
            BaseError::BadSequence => write!(f, "Function called in the wrong order."),
            BaseError::NoConnection => write!(f, "Fails to connect to next lower layer."),
            BaseError::TryAgain => write!(
                f,
                "Operation timed out; function must be called again to be completed."
            ),
            BaseError::IoError => write!(f, "IO failure."),
            BaseError::BadValue => write!(f, "A parameter has a bad value."),
            BaseError::NotPermitted => write!(f, "Operation not permitted."),
            BaseError::InvalidSessions => write!(
                f,
                "The TPM command doesn't use the number of sessions provided by the caller."
            ),
            BaseError::NoDecryptParam => write!(f, "A session with decrypt set in its SessionAttributes (TPMA_SESSION_DECRYPT bit set) was passed to a TPM command that doesn't support encryption of the first command parameter."),
            BaseError::NoEncryptParam => write!(f, "A session with encrypt set in its SessionAttributes (TPMA_SESSION_ENCRYPT bit set) was passed to a TPM command that doesn't support encryption of the first response parameter."),
            BaseError::BadSize => write!(f, "Size of a parameter is incorrect."),
            BaseError::MalformedResponse => write!(f, "Response is malformed."),
            BaseError::InsufficientContext => write!(f, "Context not large enough."),
            BaseError::InsufficientResponse => write!(f, "Response is not long enough."),
            BaseError::IncompatibleTcti => write!(f, "Unknown or unusable TCTI version."),
            BaseError::NotSupported => write!(f, "Functionality not supported."),
            BaseError::BadTctiStructure => write!(f, "TCTI context is bad."),
            BaseError::Memory => write!(f, "Memory allocation failed."),
            BaseError::BadTr => write!(f, "Invalid ObjectHandle(ESYS_TR handle)."),
            BaseError::MultipleDecryptSessions => write!(f, "More than one session with decrypt set in SessionAttributes (TPMA_SESSION_DECRYPT bit set)."),
            BaseError::MultipleEncryptSessions => write!(f, "More than one session with encrypt set in SessionAttributes (TPMA_SESSION_ENCRYPT bit set)."),
            BaseError::RspAuthFailed => write!(f, "Authorizing the TPM response failed."),
            BaseError::NoConfig => write!(f, "No config is available."),
            BaseError::BadPath => write!(f, "The provided path is bad."),
            BaseError::NotDeletable => write!(f, "The object is not deletable."),
            BaseError::PathAlreadyExists => write!(f, "The provided path already exists."),
            BaseError::KeyNotFound => write!(f, "The key was not found."),
            BaseError::SignatureVerificationFailed => write!(f, "Signature verification failed."),
            BaseError::HashMismatch => write!(f, "Hash mismatch."),
            BaseError::KeyNotDuplicable => write!(f, "Key is not duplicatable."),
            BaseError::PathNotFound => write!(f, "The path was not found."),
            BaseError::NoCert => write!(f, "No certificate."),
            BaseError::NoPcr => write!(f, "No PCR."),
            BaseError::PcrNotResettable => write!(f, "PCR not resettable."),
            BaseError::BadTemplate => write!(f, "The template is bad."),
            BaseError::AuthorizationFailed => write!(f, "Authorization failed."),
            BaseError::AuthorizationUnknown => write!(f, "Authorization is unknown."),
            BaseError::NvNotReadable => write!(f, "NV is not readable."),
            BaseError::NvTooSmall => write!(f, "NV is too small."),
            BaseError::NvNotWriteable => write!(f, "NV is not writable."),
            BaseError::PolicyUnknown => write!(f, "The policy is unknown."),
            BaseError::NvWrongType => write!(f, "The NV type is wrong."),
            BaseError::NameAlreadyExists => write!(f, "The name already exists."),
            BaseError::NoTpm => write!(f, "No TPM available."),
            BaseError::BadKey => write!(f, "The key is bad."),
            BaseError::NoHandle => write!(f, "No handle provided."),
            BaseError::NotProvisioned => write!(f, "Provisioning was not executed."),
            BaseError::AlreadyProvisioned => write!(f, "Already provisioned."),
        }
    }
}
