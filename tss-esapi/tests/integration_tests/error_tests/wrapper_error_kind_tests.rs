// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::error::WrapperErrorKind;

#[test]
fn test_display() {
    assert_eq!(
        "Parameter provided is of the wrong size.",
        format!("{}", WrapperErrorKind::WrongParamSize)
    );

    assert_eq!(
        "Some of the required parameters were not provided.",
        format!("{}", WrapperErrorKind::ParamsMissing)
    );

    assert_eq!(
        "The provided parameters have inconsistent values or variants.",
        format!("{}", WrapperErrorKind::InconsistentParams)
    );

    assert_eq!(
        "The provided parameter is not yet supported by the library.",
        format!("{}", WrapperErrorKind::UnsupportedParam)
    );

    assert_eq!(
        "The provided parameter is invalid for that type.",
        format!("{}", WrapperErrorKind::InvalidParam)
    );

    assert_eq!(
        "The TPM returned an invalid value.",
        format!("{}", WrapperErrorKind::WrongValueFromTpm)
    );

    assert_eq!(
        "Missing authorization session.",
        format!("{}", WrapperErrorKind::MissingAuthSession)
    );

    assert_eq!(
        "Invalid handle state.",
        format!("{}", WrapperErrorKind::InvalidHandleState)
    );

    assert_eq!(
        "An unexpected error occurred within the crate.",
        format!("{}", WrapperErrorKind::InternalError)
    );
}
