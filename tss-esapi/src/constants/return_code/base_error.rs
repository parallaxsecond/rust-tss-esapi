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
    GeneralFailure = TSS2_BASE_RC_GENERAL_FAILURE as u16,
    NotImplemented = TSS2_BASE_RC_NOT_IMPLEMENTED as u16,
    BadContext = TSS2_BASE_RC_BAD_CONTEXT as u16,
    AbiMismatch = TSS2_BASE_RC_ABI_MISMATCH as u16,
    BadReference = TSS2_BASE_RC_BAD_REFERENCE as u16,
    InsufficientBuffer = TSS2_BASE_RC_INSUFFICIENT_BUFFER as u16,
    BadSequence = TSS2_BASE_RC_BAD_SEQUENCE as u16,
    NoConnection = TSS2_BASE_RC_NO_CONNECTION as u16,
    TryAgain = TSS2_BASE_RC_TRY_AGAIN as u16,
    IoError = TSS2_BASE_RC_IO_ERROR as u16,
    BadValue = TSS2_BASE_RC_BAD_VALUE as u16,
    NotPermitted = TSS2_BASE_RC_NOT_PERMITTED as u16,
    InvalidSessions = TSS2_BASE_RC_INVALID_SESSIONS as u16,
    NoDecryptParam = TSS2_BASE_RC_NO_DECRYPT_PARAM as u16,
    NoEncryptParam = TSS2_BASE_RC_NO_ENCRYPT_PARAM as u16,
    BadSize = TSS2_BASE_RC_BAD_SIZE as u16,
    MalformedResponse = TSS2_BASE_RC_MALFORMED_RESPONSE as u16,
    InsufficientContext = TSS2_BASE_RC_INSUFFICIENT_CONTEXT as u16,
    InsufficientResponse = TSS2_BASE_RC_INSUFFICIENT_RESPONSE as u16,
    IncompatibleTcti = TSS2_BASE_RC_INCOMPATIBLE_TCTI as u16,
    NotSupported = TSS2_BASE_RC_NOT_SUPPORTED as u16,
    BadTctiStructure = TSS2_BASE_RC_BAD_TCTI_STRUCTURE as u16,
    Memory = TSS2_BASE_RC_MEMORY as u16,
    BadTr = TSS2_BASE_RC_BAD_TR as u16,
    MultipleDecryptSessions = TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS as u16,
    MultipleEncryptSessions = TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS as u16,
    RspAuthFailed = TSS2_BASE_RC_RSP_AUTH_FAILED as u16,
    NoConfig = TSS2_BASE_RC_NO_CONFIG as u16,
    BadPath = TSS2_BASE_RC_BAD_PATH as u16,
    NotDeletable = TSS2_BASE_RC_NOT_DELETABLE as u16,
    PathAlreadyExists = TSS2_BASE_RC_PATH_ALREADY_EXISTS as u16,
    KeyNotFound = TSS2_BASE_RC_KEY_NOT_FOUND as u16,
    SignatureVerificationFailed = TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED as u16,
    HashMismatch = TSS2_BASE_RC_HASH_MISMATCH as u16,
    KeyNotDuplicable = TSS2_BASE_RC_KEY_NOT_DUPLICABLE as u16,
    PathNotFound = TSS2_BASE_RC_PATH_NOT_FOUND as u16,
    NoCert = TSS2_BASE_RC_NO_CERT as u16,
    NoPcr = TSS2_BASE_RC_NO_PCR as u16,
    PcrNotResettable = TSS2_BASE_RC_PCR_NOT_RESETTABLE as u16,
    BadTemplate = TSS2_BASE_RC_BAD_TEMPLATE as u16,
    AuthorizationFailed = TSS2_BASE_RC_AUTHORIZATION_FAILED as u16,
    AuthorizationUnknown = TSS2_BASE_RC_AUTHORIZATION_UNKNOWN as u16,
    NvNotReadable = TSS2_BASE_RC_NV_NOT_READABLE as u16,
    NvTooSmall = TSS2_BASE_RC_NV_TOO_SMALL as u16,
    NvNotWriteable = TSS2_BASE_RC_NV_NOT_WRITEABLE as u16,
    PolicyUnknown = TSS2_BASE_RC_POLICY_UNKNOWN as u16,
    NvWrongType = TSS2_BASE_RC_NV_WRONG_TYPE as u16,
    NameAlreadyExists = TSS2_BASE_RC_NAME_ALREADY_EXISTS as u16,
    NoTpm = TSS2_BASE_RC_NO_TPM as u16,
    BadKey = TSS2_BASE_RC_BAD_KEY as u16,
    NoHandle = TSS2_BASE_RC_NO_HANDLE as u16,
    NotProvisioned = TSS2_BASE_RC_NOT_PROVISIONED as u16,
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
