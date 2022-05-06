// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
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
            TSS2_BASE_RC_TRY_AGAIN, TSS2_RESMGR_RC_LAYER,
        },
        BaseError,
    },
    error::{BaseReturnCode, ReturnCode},
    tss2_esys::TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET,
    Error, WrapperErrorKind,
};

// This basically tests BaseReturnCode as well.

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_RESMGR_RC_LAYER | $tss_rc_base_error;
        let expected_resmgr_rc = BaseReturnCode::from(BaseError::$base_error);

        assert_eq!(
            BaseError::$base_error,
            expected_resmgr_rc.into(),
            "BaseReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::ResourceManager(actual_resmgr_rc) = actual_rc {
            assert_eq!(
                expected_resmgr_rc,
                actual_resmgr_rc,
                "{} in the RESMGR layer did not convert into the expected BaseReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("RESMGR TSS2_RC layer did no not convert into ReturnCode::ResourceManager");
        }

        assert_eq!(
            expected_tss_rc,
            actual_rc.into(),
            "BaseReturnCode with {} did not convert into expected {} TSS2_RC in the RESMGR layer.",
            std::stringify!(BaseError::$base_error),
            std::stringify!($tss_rc_base_error),
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_NOT_IMPLEMENTED, BaseError::NotImplemented);
    test_valid_conversion!(TSS2_BASE_RC_BAD_CONTEXT, BaseError::BadContext);
    test_valid_conversion!(TSS2_BASE_RC_ABI_MISMATCH, BaseError::AbiMismatch);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        BaseError::InsufficientBuffer
    );
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BaseError::BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONNECTION, BaseError::NoConnection);
    test_valid_conversion!(TSS2_BASE_RC_TRY_AGAIN, BaseError::TryAgain);
    test_valid_conversion!(TSS2_BASE_RC_IO_ERROR, BaseError::IoError);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
    test_valid_conversion!(TSS2_BASE_RC_NOT_PERMITTED, BaseError::NotPermitted);
    test_valid_conversion!(TSS2_BASE_RC_INVALID_SESSIONS, BaseError::InvalidSessions);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, BaseError::NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, BaseError::NoEncryptParam);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SIZE, BaseError::BadSize);
    test_valid_conversion!(
        TSS2_BASE_RC_MALFORMED_RESPONSE,
        BaseError::MalformedResponse
    );
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
        BaseError::InsufficientContext
    );
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
        BaseError::InsufficientResponse
    );
    test_valid_conversion!(TSS2_BASE_RC_INCOMPATIBLE_TCTI, BaseError::IncompatibleTcti);
    test_valid_conversion!(TSS2_BASE_RC_NOT_SUPPORTED, BaseError::NotSupported);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TCTI_STRUCTURE, BaseError::BadTctiStructure);
    test_valid_conversion!(TSS2_BASE_RC_MEMORY, BaseError::Memory);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TR, BaseError::BadTr);
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS,
        BaseError::MultipleDecryptSessions
    );
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
        BaseError::MultipleEncryptSessions
    );
    test_valid_conversion!(TSS2_BASE_RC_RSP_AUTH_FAILED, BaseError::RspAuthFailed);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONFIG, BaseError::NoConfig);
    test_valid_conversion!(TSS2_BASE_RC_BAD_PATH, BaseError::BadPath);
    test_valid_conversion!(TSS2_BASE_RC_NOT_DELETABLE, BaseError::NotDeletable);
    test_valid_conversion!(
        TSS2_BASE_RC_PATH_ALREADY_EXISTS,
        BaseError::PathAlreadyExists
    );
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_FOUND, BaseError::KeyNotFound);
    test_valid_conversion!(
        TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
        BaseError::SignatureVerificationFailed
    );
    test_valid_conversion!(TSS2_BASE_RC_HASH_MISMATCH, BaseError::HashMismatch);
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_DUPLICABLE, BaseError::KeyNotDuplicable);
    test_valid_conversion!(TSS2_BASE_RC_PATH_NOT_FOUND, BaseError::PathNotFound);
    test_valid_conversion!(TSS2_BASE_RC_NO_CERT, BaseError::NoCert);
    test_valid_conversion!(TSS2_BASE_RC_NO_PCR, BaseError::NoPcr);
    test_valid_conversion!(TSS2_BASE_RC_PCR_NOT_RESETTABLE, BaseError::PcrNotResettable);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TEMPLATE, BaseError::BadTemplate);
    test_valid_conversion!(
        TSS2_BASE_RC_AUTHORIZATION_FAILED,
        BaseError::AuthorizationFailed
    );
    test_valid_conversion!(
        TSS2_BASE_RC_AUTHORIZATION_UNKNOWN,
        BaseError::AuthorizationUnknown
    );
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_READABLE, BaseError::NvNotReadable);
    test_valid_conversion!(TSS2_BASE_RC_NV_TOO_SMALL, BaseError::NvTooSmall);
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_WRITEABLE, BaseError::NvNotWriteable);
    test_valid_conversion!(TSS2_BASE_RC_POLICY_UNKNOWN, BaseError::PolicyUnknown);
    test_valid_conversion!(TSS2_BASE_RC_NV_WRONG_TYPE, BaseError::NvWrongType);
    test_valid_conversion!(
        TSS2_BASE_RC_NAME_ALREADY_EXISTS,
        BaseError::NameAlreadyExists
    );
    test_valid_conversion!(TSS2_BASE_RC_NO_TPM, BaseError::NoTpm);
    test_valid_conversion!(TSS2_BASE_RC_BAD_KEY, BaseError::BadKey);
    test_valid_conversion!(TSS2_BASE_RC_NO_HANDLE, BaseError::NoHandle);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc =
        TSS2_RESMGR_RC_LAYER | (TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET + 1);
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid FAPI layer resposne code did not produce the expected error"
    );
}
