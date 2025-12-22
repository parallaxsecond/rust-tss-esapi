// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use serial_test::serial;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::BaseError,
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_AUTHORIZATION_FAILED,
            TSS2_BASE_RC_AUTHORIZATION_UNKNOWN, TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_KEY,
            TSS2_BASE_RC_BAD_PATH, TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE,
            TSS2_BASE_RC_BAD_SIZE, TSS2_BASE_RC_BAD_TCTI_STRUCTURE, TSS2_BASE_RC_BAD_TEMPLATE,
            TSS2_BASE_RC_BAD_TR, TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE,
            TSS2_BASE_RC_HASH_MISMATCH, TSS2_BASE_RC_INCOMPATIBLE_TCTI,
            TSS2_BASE_RC_INSUFFICIENT_BUFFER, TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
            TSS2_BASE_RC_INSUFFICIENT_RESPONSE, TSS2_BASE_RC_INVALID_SESSIONS,
            TSS2_BASE_RC_IO_ERROR, TSS2_BASE_RC_KEY_NOT_DUPLICABLE, TSS2_BASE_RC_KEY_NOT_FOUND,
            TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_MEMORY,
            TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS, TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
            TSS2_BASE_RC_NAME_ALREADY_EXISTS, TSS2_BASE_RC_NOT_DELETABLE,
            TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_BASE_RC_NOT_PERMITTED, TSS2_BASE_RC_NOT_SUPPORTED,
            TSS2_BASE_RC_NO_CERT, TSS2_BASE_RC_NO_CONFIG, TSS2_BASE_RC_NO_CONNECTION,
            TSS2_BASE_RC_NO_DECRYPT_PARAM, TSS2_BASE_RC_NO_ENCRYPT_PARAM, TSS2_BASE_RC_NO_HANDLE,
            TSS2_BASE_RC_NO_PCR, TSS2_BASE_RC_NO_TPM, TSS2_BASE_RC_NV_NOT_READABLE,
            TSS2_BASE_RC_NV_NOT_WRITEABLE, TSS2_BASE_RC_NV_TOO_SMALL, TSS2_BASE_RC_NV_WRONG_TYPE,
            TSS2_BASE_RC_PATH_ALREADY_EXISTS, TSS2_BASE_RC_PATH_NOT_FOUND,
            TSS2_BASE_RC_PCR_NOT_RESETTABLE, TSS2_BASE_RC_POLICY_UNKNOWN,
            TSS2_BASE_RC_RSP_AUTH_FAILED, TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
            TSS2_BASE_RC_TRY_AGAIN,
        },
    },
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base:ident, $base_error_item:ident) => {
        assert_eq!(
            $tss_rc_base as u16,
            u16::from(BaseError::$base_error_item),
            "Failed to convert {} into the expected TSS2_RC value {}",
            std::stringify!(BaseError::$base_error_item),
            std::stringify!($tss_rc_base),
        );
        assert_eq!(
            BaseError::$base_error_item,
            BaseError::try_from($tss_rc_base as u16).expect(&format!(
                "Failed to convert {} into a BaseError",
                std::stringify!($tss_rc_base)
            )),
            "Conversion of {} did not result in the expected {}",
            std::stringify!($tss_rc_base),
            std::stringify!(BaseError::$base_error_item)
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_NOT_IMPLEMENTED, NotImplemented);
    test_valid_conversion!(TSS2_BASE_RC_BAD_CONTEXT, BadContext);
    test_valid_conversion!(TSS2_BASE_RC_ABI_MISMATCH, AbiMismatch);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BadReference);
    test_valid_conversion!(TSS2_BASE_RC_INSUFFICIENT_BUFFER, InsufficientBuffer);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONNECTION, NoConnection);
    test_valid_conversion!(TSS2_BASE_RC_TRY_AGAIN, TryAgain);
    test_valid_conversion!(TSS2_BASE_RC_IO_ERROR, IoError);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BadValue);
    test_valid_conversion!(TSS2_BASE_RC_NOT_PERMITTED, NotPermitted);
    test_valid_conversion!(TSS2_BASE_RC_INVALID_SESSIONS, InvalidSessions);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, NoEncryptParam);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SIZE, BadSize);
    test_valid_conversion!(TSS2_BASE_RC_MALFORMED_RESPONSE, MalformedResponse);
    test_valid_conversion!(TSS2_BASE_RC_INSUFFICIENT_CONTEXT, InsufficientContext);
    test_valid_conversion!(TSS2_BASE_RC_INSUFFICIENT_RESPONSE, InsufficientResponse);
    test_valid_conversion!(TSS2_BASE_RC_INCOMPATIBLE_TCTI, IncompatibleTcti);
    test_valid_conversion!(TSS2_BASE_RC_NOT_SUPPORTED, NotSupported);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TCTI_STRUCTURE, BadTctiStructure);
    test_valid_conversion!(TSS2_BASE_RC_MEMORY, Memory);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TR, BadTr);
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS,
        MultipleDecryptSessions
    );
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
        MultipleEncryptSessions
    );
    test_valid_conversion!(TSS2_BASE_RC_RSP_AUTH_FAILED, RspAuthFailed);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONFIG, NoConfig);
    test_valid_conversion!(TSS2_BASE_RC_BAD_PATH, BadPath);
    test_valid_conversion!(TSS2_BASE_RC_NOT_DELETABLE, NotDeletable);
    test_valid_conversion!(TSS2_BASE_RC_PATH_ALREADY_EXISTS, PathAlreadyExists);
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_FOUND, KeyNotFound);
    test_valid_conversion!(
        TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
        SignatureVerificationFailed
    );
    test_valid_conversion!(TSS2_BASE_RC_HASH_MISMATCH, HashMismatch);
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_DUPLICABLE, KeyNotDuplicable);
    test_valid_conversion!(TSS2_BASE_RC_PATH_NOT_FOUND, PathNotFound);
    test_valid_conversion!(TSS2_BASE_RC_NO_CERT, NoCert);
    test_valid_conversion!(TSS2_BASE_RC_NO_PCR, NoPcr);
    test_valid_conversion!(TSS2_BASE_RC_PCR_NOT_RESETTABLE, PcrNotResettable);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TEMPLATE, BadTemplate);
    test_valid_conversion!(TSS2_BASE_RC_AUTHORIZATION_FAILED, AuthorizationFailed);
    test_valid_conversion!(TSS2_BASE_RC_AUTHORIZATION_UNKNOWN, AuthorizationUnknown);
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_READABLE, NvNotReadable);
    test_valid_conversion!(TSS2_BASE_RC_NV_TOO_SMALL, NvTooSmall);
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_WRITEABLE, NvNotWriteable);
    test_valid_conversion!(TSS2_BASE_RC_POLICY_UNKNOWN, PolicyUnknown);
    test_valid_conversion!(TSS2_BASE_RC_NV_WRONG_TYPE, NvWrongType);
    test_valid_conversion!(TSS2_BASE_RC_NAME_ALREADY_EXISTS, NameAlreadyExists);
    test_valid_conversion!(TSS2_BASE_RC_NO_TPM, NoTpm);
    test_valid_conversion!(TSS2_BASE_RC_BAD_KEY, BadKey);
    test_valid_conversion!(TSS2_BASE_RC_NO_HANDLE, NoHandle);
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        BaseError::try_from(0),
        "Converting 0 into a BaseError did not produce the expected error"
    );
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        BaseError::try_from(0xF7FF),
        "Converting 0xF7FF into a BaseError did not produce the expected error"
    );
}
