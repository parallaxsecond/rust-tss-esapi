// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::return_code::TpmFormatZeroWarning, Error, Result};
use std::convert::TryFrom;

/// Type representing the TPM format zero warning
/// response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TpmFormatZeroWarningResponseCode {
    error_number: TpmFormatZeroWarning,
}

impl TpmFormatZeroWarningResponseCode {
    /// Returns the error number associated with the TPM
    /// format zero warning.
    pub const fn error_number(&self) -> TpmFormatZeroWarning {
        self.error_number
    }
}

impl From<TpmFormatZeroWarning> for TpmFormatZeroWarningResponseCode {
    fn from(tpm_format_zero_warning: TpmFormatZeroWarning) -> Self {
        TpmFormatZeroWarningResponseCode {
            error_number: tpm_format_zero_warning,
        }
    }
}

impl From<TpmFormatZeroWarningResponseCode> for TpmFormatZeroWarning {
    fn from(tpm_format_zero_warning_response_code: TpmFormatZeroWarningResponseCode) -> Self {
        tpm_format_zero_warning_response_code.error_number
    }
}

impl TryFrom<u8> for TpmFormatZeroWarningResponseCode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        TpmFormatZeroWarning::try_from(value).map(TpmFormatZeroWarningResponseCode::from)
    }
}

impl From<TpmFormatZeroWarningResponseCode> for u8 {
    fn from(tpm_format_zero_warning_response_code: TpmFormatZeroWarningResponseCode) -> u8 {
        TpmFormatZeroWarning::from(tpm_format_zero_warning_response_code).into()
    }
}

impl std::error::Error for TpmFormatZeroWarningResponseCode {}

impl std::fmt::Display for TpmFormatZeroWarningResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // These display values are taken from the specification. Some have been
        // changed so that the sentence starts with a capital letter and ends with
        // period.
        match self.error_number {
            TpmFormatZeroWarning::ContextGap => write!(f, "Gap for context ID is too large."),
            TpmFormatZeroWarning::ObjectMemory => write!(f, "Out of memory for object contexts."),
            TpmFormatZeroWarning::SessionMemory => write!(f, "Out of memory for session contexts."),
            TpmFormatZeroWarning::Memory => write!(f, "Out of shared object or session memory or need space for internal operations."),
            TpmFormatZeroWarning::SessionHandles => write!(f, "Out of session handles."),
            TpmFormatZeroWarning::ObjectHandles => write!(f, "Out of object handles."),
            TpmFormatZeroWarning::Locality => write!(f, "Bad locality."),
            TpmFormatZeroWarning::Yielded => write!(f, "The TPM has suspended operation on the command; forward progress was made and the command may be retried."),
            TpmFormatZeroWarning::Canceled => write!(f, "The command was canceled."),
            TpmFormatZeroWarning::Testing => write!(f, "TPM is performing self-tests."),
            TpmFormatZeroWarning::ReferenceH0 => write!(f, "The 1st handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH1 => write!(f, "The 2nd handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH2 => write!(f, "The 3rd handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH3 => write!(f, "The 4th handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH4 => write!(f, "The 5th handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH5 => write!(f, "The 6th handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceH6 => write!(f, "The 7th handle in the handle area references a transient object or session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS0 => write!(f, "The 1st authorization session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS1 => write!(f, "The 2nd authorization session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS2 => write!(f, "The 3rd authorization session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS3 => write!(f, "The 4th authorization session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS4 => write!(f, "The 5th session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS5 => write!(f, "The 6th session handle references a session that is not loaded."),
            TpmFormatZeroWarning::ReferenceS6 => write!(f, "The 7th authorization session handle references a session that is not loaded."),
            TpmFormatZeroWarning::NvRate => write!(f, "The TPM is rate-limiting accesses to prevent wearout of NV."),
            TpmFormatZeroWarning::Lockout => write!(f, "Authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode."),
            TpmFormatZeroWarning::Retry => write!(f, "The TPM was not able to start the command."),
            TpmFormatZeroWarning::NvUnavailable => write!(f, "The command may require writing of NV and NV is not current accessible."),
        }
    }
}
