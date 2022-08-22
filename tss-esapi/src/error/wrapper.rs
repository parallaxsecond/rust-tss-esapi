// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
/// List of error types that might occur in the wrapper.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrapperErrorKind {
    /// Returned when a size or length-defined parameter does not conform with the size
    /// restrictions for it.
    WrongParamSize,
    /// Returned when a required parameter was not passed, usually to a builder.
    ParamsMissing,
    /// Returned when two or more parameters have inconsistent values or variants.
    InconsistentParams,
    /// Returned when the value of a parameter is not yet supported.
    UnsupportedParam,
    /// Returned when the value of a parameter is invalid for that type.
    InvalidParam,
    /// Returned when the TPM returns an invalid value from a call.
    WrongValueFromTpm,
    /// Returned when a session for authentication has not been set
    /// before the call is made.
    MissingAuthSession,
    /// Returned when a handle is required to be in a specific state
    /// (i.g. Open, Flushed, Closed) but it is not.
    InvalidHandleState,
    /// An unexpected internal error occurred.
    InternalError,
}

impl std::fmt::Display for WrapperErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WrapperErrorKind::WrongParamSize => {
                write!(f, "parameter provided is of the wrong size")
            }
            WrapperErrorKind::ParamsMissing => {
                write!(f, "some of the required parameters were not provided")
            }
            WrapperErrorKind::InconsistentParams => write!(
                f,
                "the provided parameters have inconsistent values or variants"
            ),
            WrapperErrorKind::UnsupportedParam => write!(
                f,
                "the provided parameter is not yet supported by the library"
            ),
            WrapperErrorKind::InvalidParam => {
                write!(f, "the provided parameter is invalid for that type.")
            }
            WrapperErrorKind::WrongValueFromTpm => write!(f, "the TPM returned an invalid value."),
            WrapperErrorKind::MissingAuthSession => write!(f, "Missing authorization session"),
            WrapperErrorKind::InvalidHandleState => write!(f, "Invalid handle state"),
            WrapperErrorKind::InternalError => {
                write!(f, "an unexpected error occurred within the crate")
            }
        }
    }
}

impl std::error::Error for WrapperErrorKind {}
