// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.

use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE,
            TSS2_BASE_RC_BAD_TCTI_STRUCTURE, TSS2_BASE_RC_BAD_TEMPLATE, TSS2_BASE_RC_BAD_VALUE,
            TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_INCOMPATIBLE_TCTI,
            TSS2_BASE_RC_INSUFFICIENT_BUFFER, TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
            TSS2_BASE_RC_INSUFFICIENT_RESPONSE, TSS2_BASE_RC_INVALID_SESSIONS,
            TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_NO_DECRYPT_PARAM,
            TSS2_BASE_RC_NO_ENCRYPT_PARAM, TSS2_SYS_RC_LAYER,
        },
        BaseError,
    },
    error::{BaseReturnCode, ReturnCode, SapiReturnCode},
    tss2_esys::TSS2_RC,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_SYS_RC_LAYER | $tss_rc_base_error;
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);
        let expected_sapi_rc = SapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into SapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            expected_sapi_rc.into(),
            "SapiReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_sapi_rc,
            SapiReturnCode::try_from(expected_base_rc).expect(&format!(
                "BaseReturnCode with {} failed to convert into an SapiReturnCode",
                std::stringify!(BaseError::$base_error)
            )),
            "BaseReturnCode with {} failed to convert into the expected SapiReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            expected_sapi_rc.into(),
            "SapiReturnCode with {} failed to convert into the expected BaseReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Sapi(actual_sapi_rc) = actual_rc {
            assert_eq!(
                expected_sapi_rc,
                actual_sapi_rc,
                "{} in the SAPI layer did not convert into the expected SapiReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("SAPI TSS2_RC layer did no convert into ReturnCode::Sapi");
        }

        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual_rc),
            "SapiReturnCode with {} did not convert into expected {} TSS2_RC in the SAPI layer.",
            std::stringify!(BaseError::$base_error),
            std::stringify!($tss_rc_base_error),
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_ABI_MISMATCH, BaseError::AbiMismatch);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        BaseError::InsufficientBuffer
    );
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BaseError::BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
    test_valid_conversion!(TSS2_BASE_RC_INVALID_SESSIONS, BaseError::InvalidSessions);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, BaseError::NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, BaseError::NoEncryptParam);
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
    test_valid_conversion!(TSS2_BASE_RC_BAD_TCTI_STRUCTURE, BaseError::BadTctiStructure);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc = TSS2_SYS_RC_LAYER | TSS2_BASE_RC_BAD_TEMPLATE;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid SAPI layer response code did not produce the expected error"
    );
}

macro_rules! test_base_error {
    (BaseError::$base_error:ident) => {
        let sapi_rc = SapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into SapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            sapi_rc.base_error(),
            "`base_error` method did not return the expected value."
        );
    };
}

#[test]
fn test_base_error_method() {
    test_base_error!(BaseError::GeneralFailure);
    test_base_error!(BaseError::AbiMismatch);
    test_base_error!(BaseError::BadReference);
    test_base_error!(BaseError::InsufficientBuffer);
    test_base_error!(BaseError::BadSequence);
    test_base_error!(BaseError::BadValue);
    test_base_error!(BaseError::InvalidSessions);
    test_base_error!(BaseError::NoDecryptParam);
    test_base_error!(BaseError::NoEncryptParam);
    test_base_error!(BaseError::MalformedResponse);
    test_base_error!(BaseError::InsufficientContext);
    test_base_error!(BaseError::InsufficientResponse);
    test_base_error!(BaseError::IncompatibleTcti);
    test_base_error!(BaseError::BadTctiStructure);
}
