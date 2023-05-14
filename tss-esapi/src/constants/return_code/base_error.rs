// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_ALREADY_PROVISIONED,
        TSS2_BASE_RC_AUTHORIZATION_FAILED, TSS2_BASE_RC_AUTHORIZATION_UNKNOWN,
        TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_KEY, TSS2_BASE_RC_BAD_PATH,
        TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE, TSS2_BASE_RC_BAD_SIZE,
        TSS2_BASE_RC_BAD_TCTI_STRUCTURE, TSS2_BASE_RC_BAD_TEMPLATE, TSS2_BASE_RC_BAD_TR,
        TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_HASH_MISMATCH,
        TSS2_BASE_RC_INCOMPATIBLE_TCTI, TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        TSS2_BASE_RC_INSUFFICIENT_CONTEXT, TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
        TSS2_BASE_RC_INVALID_SESSIONS, TSS2_BASE_RC_IO_ERROR, TSS2_BASE_RC_KEY_NOT_DUPLICABLE,
        TSS2_BASE_RC_KEY_NOT_FOUND, TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_MEMORY,
        TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS, TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
        TSS2_BASE_RC_NAME_ALREADY_EXISTS, TSS2_BASE_RC_NOT_DELETABLE, TSS2_BASE_RC_NOT_IMPLEMENTED,
        TSS2_BASE_RC_NOT_PERMITTED, TSS2_BASE_RC_NOT_PROVISIONED, TSS2_BASE_RC_NOT_SUPPORTED,
        TSS2_BASE_RC_NO_CERT, TSS2_BASE_RC_NO_CONFIG, TSS2_BASE_RC_NO_CONNECTION,
        TSS2_BASE_RC_NO_DECRYPT_PARAM, TSS2_BASE_RC_NO_ENCRYPT_PARAM, TSS2_BASE_RC_NO_HANDLE,
        TSS2_BASE_RC_NO_PCR, TSS2_BASE_RC_NO_TPM, TSS2_BASE_RC_NV_NOT_READABLE,
        TSS2_BASE_RC_NV_NOT_WRITEABLE, TSS2_BASE_RC_NV_TOO_SMALL, TSS2_BASE_RC_NV_WRONG_TYPE,
        TSS2_BASE_RC_PATH_ALREADY_EXISTS, TSS2_BASE_RC_PATH_NOT_FOUND,
        TSS2_BASE_RC_PCR_NOT_RESETTABLE, TSS2_BASE_RC_POLICY_UNKNOWN, TSS2_BASE_RC_RSP_AUTH_FAILED,
        TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED, TSS2_BASE_RC_TRY_AGAIN,
    },
    Error, Result, WrapperErrorKind,
};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing the base error values for the TSS
/// return code.
///
/// # Details
/// These values are only returned by non TPM layers of the
/// software stack. For some layers only a subset of these
/// are used.
///
/// Note:
/// In order to create a complete TSS return value for non
/// TPM layers. This error code needs to be combined with the
/// information about the layer that produced it.
///
/// TCG TSS 2.0 Overview and Common Structures Specification:
///
/// "For return values other than SUCCESS, the second most significant
/// byte of the return value is a layer code indicating the software
/// layer that generated the error."
///
/// "Base return codes.
/// These base codes indicate the error that occurred. They are
/// logical-ORed with a layer code to produce the TSS2 return value."
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum BaseError {
    /// Catch all for all errors not otherwise specified.
    GeneralFailure = TSS2_BASE_RC_GENERAL_FAILURE as u16,
    /// If called functionality isn't implemented.
    NotImplemented = TSS2_BASE_RC_NOT_IMPLEMENTED as u16,
    /// A context structure is bad.
    BadContext = TSS2_BASE_RC_BAD_CONTEXT as u16,
    /// Passed in ABI version doesn't match called module's ABI version.
    AbiMismatch = TSS2_BASE_RC_ABI_MISMATCH as u16,
    /// A pointer is NULL that isn't allowed to be NULL.
    BadReference = TSS2_BASE_RC_BAD_REFERENCE as u16,
    /// A buffer isn't large enough.
    InsufficientBuffer = TSS2_BASE_RC_INSUFFICIENT_BUFFER as u16,
    /// Function called in the wrong order.
    BadSequence = TSS2_BASE_RC_BAD_SEQUENCE as u16,
    /// Fails to connect to next lower layer.
    NoConnection = TSS2_BASE_RC_NO_CONNECTION as u16,
    /// Operation timed out; function must be called again to be completed.
    TryAgain = TSS2_BASE_RC_TRY_AGAIN as u16,
    /// IO failure.
    IoError = TSS2_BASE_RC_IO_ERROR as u16,
    /// A parameter has a bad value.
    BadValue = TSS2_BASE_RC_BAD_VALUE as u16,
    /// Operation not permitted.
    NotPermitted = TSS2_BASE_RC_NOT_PERMITTED as u16,
    /// The TPM command doesn't use the number of sessions provided by the caller.
    InvalidSessions = TSS2_BASE_RC_INVALID_SESSIONS as u16,
    /// A session with `decrypt` set in its [SessionAttributes](crate::attributes::SessionAttributes)
    /// (TPMA_SESSION_DECRYPT bit set) was passed to a TPM command that doesn't support encryption
    /// of the first command parameter.
    NoDecryptParam = TSS2_BASE_RC_NO_DECRYPT_PARAM as u16,
    /// A session with `encrypt` set in its [SessionAttributes](crate::attributes::SessionAttributes)
    /// (TPMA_SESSION_ENCRYPT bit set) was passed to a TPM command that doesn't support encryption
    /// of the first response parameter.
    NoEncryptParam = TSS2_BASE_RC_NO_ENCRYPT_PARAM as u16,
    /// If size of a parameter is incorrect.
    BadSize = TSS2_BASE_RC_BAD_SIZE as u16,
    /// Response is malformed.
    MalformedResponse = TSS2_BASE_RC_MALFORMED_RESPONSE as u16,
    /// Context not large enough.
    InsufficientContext = TSS2_BASE_RC_INSUFFICIENT_CONTEXT as u16,
    /// Response is not long enough.
    InsufficientResponse = TSS2_BASE_RC_INSUFFICIENT_RESPONSE as u16,
    /// Unknown or unusable TCTI version.
    IncompatibleTcti = TSS2_BASE_RC_INCOMPATIBLE_TCTI as u16,
    /// Functionality not supported.
    NotSupported = TSS2_BASE_RC_NOT_SUPPORTED as u16,
    /// TCTI context is bad.
    BadTctiStructure = TSS2_BASE_RC_BAD_TCTI_STRUCTURE as u16,
    /// Memory allocation failed.
    Memory = TSS2_BASE_RC_MEMORY as u16,
    /// Invalid [ObjectHandle](crate::handles::ObjectHandle)
    /// (ESYS_TR handle).
    BadTr = TSS2_BASE_RC_BAD_TR as u16,
    /// More than one session with `decrypt` set in its [SessionAttributes](crate::attributes::SessionAttributes)
    /// (TPMA_SESSION_DECRYPT bit set).
    MultipleDecryptSessions = TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS as u16,
    /// More than one session with encrypt set its [SessionAttributes](crate::attributes::SessionAttributes)
    /// (TPMA_SESSION_ENCRYPT bit set).
    MultipleEncryptSessions = TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS as u16,
    /// Authorizing the TPM response failed.
    RspAuthFailed = TSS2_BASE_RC_RSP_AUTH_FAILED as u16,
    /// No config is available.
    NoConfig = TSS2_BASE_RC_NO_CONFIG as u16,
    /// The provided path is bad.
    BadPath = TSS2_BASE_RC_BAD_PATH as u16,
    /// The object is not deletable.
    NotDeletable = TSS2_BASE_RC_NOT_DELETABLE as u16,
    /// The provided path already exists.
    PathAlreadyExists = TSS2_BASE_RC_PATH_ALREADY_EXISTS as u16,
    /// The key was not found.
    KeyNotFound = TSS2_BASE_RC_KEY_NOT_FOUND as u16,
    /// Signature verification failed.
    SignatureVerificationFailed = TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED as u16,
    /// Hash mismatch.
    HashMismatch = TSS2_BASE_RC_HASH_MISMATCH as u16,
    /// Key is not duplicatable.
    KeyNotDuplicable = TSS2_BASE_RC_KEY_NOT_DUPLICABLE as u16,
    /// The path was not found.
    PathNotFound = TSS2_BASE_RC_PATH_NOT_FOUND as u16,
    /// No certificate.
    NoCert = TSS2_BASE_RC_NO_CERT as u16,
    /// No PCR.
    NoPcr = TSS2_BASE_RC_NO_PCR as u16,
    /// PCR not resettable.
    PcrNotResettable = TSS2_BASE_RC_PCR_NOT_RESETTABLE as u16,
    /// The template is bad.
    BadTemplate = TSS2_BASE_RC_BAD_TEMPLATE as u16,
    /// Authorization failed.
    AuthorizationFailed = TSS2_BASE_RC_AUTHORIZATION_FAILED as u16,
    /// Authorization is unknown.
    AuthorizationUnknown = TSS2_BASE_RC_AUTHORIZATION_UNKNOWN as u16,
    /// NV is not readable.
    NvNotReadable = TSS2_BASE_RC_NV_NOT_READABLE as u16,
    /// NV is too small.
    NvTooSmall = TSS2_BASE_RC_NV_TOO_SMALL as u16,
    /// NV is not writable.
    NvNotWriteable = TSS2_BASE_RC_NV_NOT_WRITEABLE as u16,
    /// The policy is unknown.
    PolicyUnknown = TSS2_BASE_RC_POLICY_UNKNOWN as u16,
    /// The NV type is wrong.
    NvWrongType = TSS2_BASE_RC_NV_WRONG_TYPE as u16,
    /// The name already exists.
    NameAlreadyExists = TSS2_BASE_RC_NAME_ALREADY_EXISTS as u16,
    /// No TPM available.
    NoTpm = TSS2_BASE_RC_NO_TPM as u16,
    /// The key is bad.
    BadKey = TSS2_BASE_RC_BAD_KEY as u16,
    /// No handle provided.
    NoHandle = TSS2_BASE_RC_NO_HANDLE as u16,
    /// Provisioning was not executed.
    NotProvisioned = TSS2_BASE_RC_NOT_PROVISIONED as u16,
    /// Already provisioned.
    AlreadyProvisioned = TSS2_BASE_RC_ALREADY_PROVISIONED as u16,
}

impl TryFrom<u16> for BaseError {
    type Error = Error;

    fn try_from(value: u16) -> Result<BaseError> {
        BaseError::from_u16(value).ok_or_else(|| {
            error!("Value = {} did not match any TSS base return code", value);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<BaseError> for u16 {
    fn from(tss_base_error: BaseError) -> u16 {
        // The values are well defined so this cannot fail
        tss_base_error.to_u16().unwrap()
    }
}
