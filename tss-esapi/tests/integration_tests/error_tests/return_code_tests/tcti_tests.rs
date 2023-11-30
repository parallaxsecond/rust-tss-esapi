// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.

use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_REFERENCE,
            TSS2_BASE_RC_BAD_SEQUENCE, TSS2_BASE_RC_BAD_TEMPLATE, TSS2_BASE_RC_BAD_VALUE,
            TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_INSUFFICIENT_BUFFER, TSS2_BASE_RC_IO_ERROR,
            TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_NOT_IMPLEMENTED,
            TSS2_BASE_RC_NOT_PERMITTED, TSS2_BASE_RC_NOT_SUPPORTED, TSS2_BASE_RC_NO_CONNECTION,
            TSS2_BASE_RC_TRY_AGAIN, TSS2_TCTI_RC_LAYER,
        },
        BaseError,
    },
    error::{BaseReturnCode, ReturnCode, TctiReturnCode},
    tss2_esys::TSS2_RC,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_TCTI_RC_LAYER | $tss_rc_base_error;
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);
        let expected_tcti_rc = TctiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into TctiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            expected_tcti_rc.into(),
            "TctiReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_tcti_rc,
            TctiReturnCode::try_from(expected_base_rc).expect(&format!(
                "BaseReturnCode with {} failed to convert into an TctiReturnCode",
                std::stringify!(BaseError::$base_error)
            )),
            "BaseReturnCode with {} failed to convert into the expected TctiReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            expected_tcti_rc.into(),
            "TctiReturnCode with {} failed to convert into the expected BaseReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Tcti(actual_tcti_rc) = actual_rc {
            assert_eq!(
                expected_tcti_rc,
                actual_tcti_rc,
                "{} in the TCTI layer did not convert into the expected TctiReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("TCTI TSS2_RC layer did no convert into ReturnCode::Tcti");
        }

        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual_rc),
            "TctiReturnCode with {} did not convert into expected {} TSS2_RC in the TCTI layer.",
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
    test_valid_conversion!(
        TSS2_BASE_RC_MALFORMED_RESPONSE,
        BaseError::MalformedResponse
    );
    test_valid_conversion!(TSS2_BASE_RC_NOT_SUPPORTED, BaseError::NotSupported);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc = TSS2_TCTI_RC_LAYER | TSS2_BASE_RC_BAD_TEMPLATE;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid TCTI layer response code did not produce the expected error"
    );
}

macro_rules! test_base_error {
    (BaseError::$base_error:ident) => {
        let tcti_rc = TctiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into TctiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            tcti_rc.base_error(),
            "`base_error` method did not return the expected value."
        );
    };
}

#[test]
fn test_base_error_method() {
    test_base_error!(BaseError::GeneralFailure);
    test_base_error!(BaseError::NotImplemented);
    test_base_error!(BaseError::BadContext);
    test_base_error!(BaseError::AbiMismatch);
    test_base_error!(BaseError::BadReference);
    test_base_error!(BaseError::InsufficientBuffer);
    test_base_error!(BaseError::BadSequence);
    test_base_error!(BaseError::NoConnection);
    test_base_error!(BaseError::TryAgain);
    test_base_error!(BaseError::IoError);
    test_base_error!(BaseError::BadValue);
    test_base_error!(BaseError::NotPermitted);
    test_base_error!(BaseError::MalformedResponse);
    test_base_error!(BaseError::NotSupported);
}
