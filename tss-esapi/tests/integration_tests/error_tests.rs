// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod return_code_tests;
mod wrapper_error_kind_tests;

use std::{convert::TryFrom, error::Error};

use tss_esapi::{
    constants::tss::{TPM2_RC_INITIALIZE, TSS2_TPM_RC_LAYER},
    error::{ReturnCode, WrapperErrorKind},
};

#[test]
fn test_error_trait_implementation() {
    // The Error type is only expected to forward everything to the
    // underlying error types.
    let expected_wrapper_error_kind = WrapperErrorKind::InconsistentParams;
    let wrapper_error = tss_esapi::Error::WrapperError(expected_wrapper_error_kind);
    let actual_wrapper_error_kind = wrapper_error
        .source()
        .expect("`source()` for an Error of type WrapperError returned None.");
    assert_eq!(
        format!("{}", expected_wrapper_error_kind),
        format!("{}", actual_wrapper_error_kind)
    );

    let expected_return_code = ReturnCode::try_from(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE)
        .expect("Failed to convert TSS return code into a ReturnCode object.");
    let tss_error = tss_esapi::Error::TssError(expected_return_code);
    let actual_return_code = tss_error
        .source()
        .expect("`source()` for an Error of type ReturnCode returned None.");
    assert_eq!(
        format!("{}", expected_return_code),
        format!("{}", actual_return_code)
    );
}

#[test]
fn test_display_trait_implementation() {
    // The Error type is only expected to forward everything to the
    // underlying error types.
    let expected_wrapper_error_kind = WrapperErrorKind::InconsistentParams;
    let wrapper_error = tss_esapi::Error::WrapperError(expected_wrapper_error_kind);
    assert_eq!(
        format!("{}", expected_wrapper_error_kind),
        format!("{}", wrapper_error)
    );

    let expected_return_code = ReturnCode::try_from(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE)
        .expect("Failed to convert TSS return code into a ReturnCode object.");
    let tss_error = tss_esapi::Error::TssError(expected_return_code);
    assert_eq!(
        format!("{}", expected_return_code),
        format!("{}", tss_error)
    );
}
