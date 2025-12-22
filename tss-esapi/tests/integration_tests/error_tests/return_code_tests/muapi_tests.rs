// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.

use serial_test::serial;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SIZE, TSS2_BASE_RC_BAD_TEMPLATE,
            TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE, TSS2_BASE_RC_INSUFFICIENT_BUFFER,
            TSS2_MU_RC_LAYER,
        },
        BaseError,
    },
    error::{BaseReturnCode, MuapiReturnCode, ReturnCode},
    tss2_esys::TSS2_RC,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_MU_RC_LAYER | $tss_rc_base_error;
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);
        let expected_muapi_rc = MuapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into MuapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            expected_muapi_rc.into(),
            "MuapiReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_muapi_rc,
            MuapiReturnCode::try_from(expected_base_rc).expect(&format!(
                "BaseReturnCode with {} failed to convert into an MuapiReturnCode",
                std::stringify!(BaseError::$base_error)
            )),
            "BaseReturnCode with {} failed to convert into the expected MuapiReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            expected_muapi_rc.into(),
            "MuapiReturnCode with {} failed to convert into the expected BaseReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Mu(actual_muapi_rc) = actual_rc {
            assert_eq!(
                expected_muapi_rc,
                actual_muapi_rc,
                "{} in the MUAPI layer did not convert into the expected MuapiReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("MUAPI TSS2_RC layer did no convert into ReturnCode::Mu");
        }

        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual_rc),
            "{} did not convert into expected {} in TSS2_RC MUAPI layer.",
            std::stringify!(ReturnCode::Mu(MuapiReturnCode::$muapi_rc_item)),
            std::stringify!($tss_rc_base_error),
        );
    };
}

#[test]
#[serial]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        BaseError::InsufficientBuffer
    );
    test_valid_conversion!(TSS2_BASE_RC_BAD_SIZE, BaseError::BadSize);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
}

#[test]
#[serial]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc = TSS2_MU_RC_LAYER | TSS2_BASE_RC_BAD_TEMPLATE;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid MUAPI layer response code did not produce the expected error"
    );
}

macro_rules! test_base_error {
    (BaseError::$base_error:ident) => {
        let muapi_rc = MuapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into MuapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            muapi_rc.base_error(),
            "`base_error` method did not return the expected value."
        );
    };
}

#[test]
#[serial]
fn test_base_error_method() {
    test_base_error!(BaseError::GeneralFailure);
    test_base_error!(BaseError::BadReference);
    test_base_error!(BaseError::InsufficientBuffer);
    test_base_error!(BaseError::BadSize);
    test_base_error!(BaseError::BadValue);
}
