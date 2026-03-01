// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use serial_test::serial;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_ALREADY_PROVISIONED,
            TSS2_BASE_RC_AUTHORIZATION_FAILED, TSS2_BASE_RC_AUTHORIZATION_UNKNOWN,
            TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_KEY, TSS2_BASE_RC_BAD_PATH,
            TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE, TSS2_BASE_RC_BAD_TEMPLATE,
            TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_HASH_MISMATCH,
            TSS2_BASE_RC_IO_ERROR, TSS2_BASE_RC_KEY_NOT_DUPLICABLE, TSS2_BASE_RC_KEY_NOT_FOUND,
            TSS2_BASE_RC_MEMORY, TSS2_BASE_RC_NAME_ALREADY_EXISTS, TSS2_BASE_RC_NOT_DELETABLE,
            TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_BASE_RC_NOT_PROVISIONED, TSS2_BASE_RC_NO_CERT,
            TSS2_BASE_RC_NO_CONFIG, TSS2_BASE_RC_NO_DECRYPT_PARAM, TSS2_BASE_RC_NO_ENCRYPT_PARAM,
            TSS2_BASE_RC_NO_HANDLE, TSS2_BASE_RC_NO_PCR, TSS2_BASE_RC_NO_TPM,
            TSS2_BASE_RC_NV_NOT_READABLE, TSS2_BASE_RC_NV_NOT_WRITEABLE, TSS2_BASE_RC_NV_TOO_SMALL,
            TSS2_BASE_RC_NV_WRONG_TYPE, TSS2_BASE_RC_PATH_ALREADY_EXISTS,
            TSS2_BASE_RC_PATH_NOT_FOUND, TSS2_BASE_RC_PCR_NOT_RESETTABLE,
            TSS2_BASE_RC_POLICY_UNKNOWN, TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
            TSS2_BASE_RC_TRY_AGAIN, TSS2_FEATURE_RC_LAYER,
        },
        BaseError,
    },
    error::{BaseReturnCode, FapiReturnCode, ReturnCode},
    tss2_esys::TSS2_RC,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_FEATURE_RC_LAYER | $tss_rc_base_error;
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);
        let expected_fapi_rc = FapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into FapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            expected_fapi_rc.into(),
            "FapiReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_fapi_rc,
            FapiReturnCode::try_from(expected_base_rc).expect(&format!(
                "BaseReturnCode with {} failed to convert into an FapiReturnCode",
                std::stringify!(BaseError::$base_error)
            )),
            "BaseReturnCode with {} failed to convert into the expected FapiReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            expected_fapi_rc.into(),
            "FapiReturnCode with {} failed to convert into the expected BaseReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Fapi(actual_fapi_rc) = actual_rc {
            assert_eq!(
                expected_fapi_rc,
                actual_fapi_rc,
                "{} in the FAPI layer did not convert into the expected FapiReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("FAPI TSS2_RC layer did no convert into ReturnCode::Fapi");
        }

        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual_rc),
            "FapiReturnCode with {} did not convert into expected {} TSS2_RC in the FAPI layer.",
            std::stringify!(BaseError::$base_error),
            std::stringify!($tss_rc_base_error),
        );
    };
}

#[test]
#[serial]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_NOT_IMPLEMENTED, BaseError::NotImplemented);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BaseError::BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_IO_ERROR, BaseError::IoError);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, BaseError::NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, BaseError::NoEncryptParam);
    test_valid_conversion!(TSS2_BASE_RC_MEMORY, BaseError::Memory);
    test_valid_conversion!(TSS2_BASE_RC_BAD_CONTEXT, BaseError::BadContext);
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
    test_valid_conversion!(TSS2_BASE_RC_TRY_AGAIN, BaseError::TryAgain);
    test_valid_conversion!(TSS2_BASE_RC_BAD_KEY, BaseError::BadKey);
    test_valid_conversion!(TSS2_BASE_RC_NO_HANDLE, BaseError::NoHandle);
    test_valid_conversion!(TSS2_BASE_RC_NOT_PROVISIONED, BaseError::NotProvisioned);
    test_valid_conversion!(
        TSS2_BASE_RC_ALREADY_PROVISIONED,
        BaseError::AlreadyProvisioned
    );
}

#[test]
#[serial]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc = TSS2_FEATURE_RC_LAYER | TSS2_BASE_RC_ABI_MISMATCH;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid FAPI layer response code did not produce the expected error"
    );
}

macro_rules! test_base_error {
    (BaseError::$base_error:ident) => {
        let fapi_rc = FapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into FapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            fapi_rc.base_error(),
            "`base_error` method did not return the expected value."
        );
    };
}

#[test]
#[serial]
fn test_base_error_method() {
    test_base_error!(BaseError::GeneralFailure);
    test_base_error!(BaseError::NotImplemented);
    test_base_error!(BaseError::BadReference);
    test_base_error!(BaseError::BadSequence);
    test_base_error!(BaseError::IoError);
    test_base_error!(BaseError::BadValue);
    test_base_error!(BaseError::NoDecryptParam);
    test_base_error!(BaseError::NoEncryptParam);
    test_base_error!(BaseError::Memory);
    test_base_error!(BaseError::BadContext);
    test_base_error!(BaseError::NoConfig);
    test_base_error!(BaseError::BadPath);
    test_base_error!(BaseError::NotDeletable);
    test_base_error!(BaseError::PathAlreadyExists);
    test_base_error!(BaseError::KeyNotFound);
    test_base_error!(BaseError::SignatureVerificationFailed);
    test_base_error!(BaseError::HashMismatch);
    test_base_error!(BaseError::KeyNotDuplicable);
    test_base_error!(BaseError::PathNotFound);
    test_base_error!(BaseError::NoCert);
    test_base_error!(BaseError::NoPcr);
    test_base_error!(BaseError::PcrNotResettable);
    test_base_error!(BaseError::BadTemplate);
    test_base_error!(BaseError::AuthorizationFailed);
    test_base_error!(BaseError::AuthorizationUnknown);
    test_base_error!(BaseError::NvNotReadable);
    test_base_error!(BaseError::NvTooSmall);
    test_base_error!(BaseError::NvNotWriteable);
    test_base_error!(BaseError::PolicyUnknown);
    test_base_error!(BaseError::NvWrongType);
    test_base_error!(BaseError::NameAlreadyExists);
    test_base_error!(BaseError::NoTpm);
    test_base_error!(BaseError::TryAgain);
    test_base_error!(BaseError::BadKey);
    test_base_error!(BaseError::NoHandle);
    test_base_error!(BaseError::NotProvisioned);
    test_base_error!(BaseError::AlreadyProvisioned);
}
