// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::return_code::TpmFormatZeroError, Error, Result};
use std::convert::TryFrom;

/// Type representing the TPM format zero error
/// response code.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct TpmFormatZeroErrorResponseCode {
    error_number: TpmFormatZeroError,
}

impl TpmFormatZeroErrorResponseCode {
    /// Returns the error number associated with the TPM format zero
    /// return code.
    pub const fn error_number(&self) -> TpmFormatZeroError {
        self.error_number
    }
}

impl From<TpmFormatZeroError> for TpmFormatZeroErrorResponseCode {
    fn from(tpm_format_zero_error: TpmFormatZeroError) -> Self {
        TpmFormatZeroErrorResponseCode {
            error_number: tpm_format_zero_error,
        }
    }
}

impl From<TpmFormatZeroErrorResponseCode> for TpmFormatZeroError {
    fn from(tpm_format_zero_error_response_code: TpmFormatZeroErrorResponseCode) -> Self {
        tpm_format_zero_error_response_code.error_number
    }
}

impl TryFrom<u8> for TpmFormatZeroErrorResponseCode {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        TpmFormatZeroError::try_from(value).map(TpmFormatZeroErrorResponseCode::from)
    }
}

impl From<TpmFormatZeroErrorResponseCode> for u8 {
    fn from(tpm_format_zero_error_response_code: TpmFormatZeroErrorResponseCode) -> u8 {
        TpmFormatZeroError::from(tpm_format_zero_error_response_code).into()
    }
}

impl std::error::Error for TpmFormatZeroErrorResponseCode {}

impl std::fmt::Display for TpmFormatZeroErrorResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.error_number {
            TpmFormatZeroError::Initialize => write!(f, "TPM not initialized by TPM2_Startup or already initialized"),
            TpmFormatZeroError::Failure => write!(f, "commands not being accepted because of a TPM failure. NOTE: This may be returned by TPM2_GetTestResult() as the testResultparameter"),
            TpmFormatZeroError::Sequence => write!(f, "improper use of a sequence handle"),
            TpmFormatZeroError::Private => write!(f, "not currently used"),
            TpmFormatZeroError::Hmac => write!(f, "not currently used"),
            TpmFormatZeroError::Disabled => write!(f, "the command is disabled"),
            TpmFormatZeroError::Exclusive => write!(f, "command failed because audit sequence required exclusivity"),
            TpmFormatZeroError::AuthType => write!(f, "authorization handle is not correct for command"),
            TpmFormatZeroError::AuthMissing => write!(f, "command requires an authorization session for handle and it is not present"),
            TpmFormatZeroError::Policy => write!(f, "policy failure in math operation or an invalid authPolicy value"),
            TpmFormatZeroError::Pcr => write!(f, "PCR check fail"),
            TpmFormatZeroError::PcrChanged => write!(f, "PCR have changed since checked"),
            TpmFormatZeroError::Upgrade => write!(f, "for all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode"),
            TpmFormatZeroError::TooManyContexts => write!(f, "context ID counter is at maximum"),
            TpmFormatZeroError::AuthUnavailable => write!(f, "authValue or authPolicy is not available for selected entity"),
            TpmFormatZeroError::Reboot => write!(f, "a _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation"),
            TpmFormatZeroError::Unbalanced => write!(f, "the protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm"),
            TpmFormatZeroError::CommandSize => write!(f, "command commandSizevalue is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header"),
            TpmFormatZeroError::CommandCode => write!(f, "command code not supported"),
            TpmFormatZeroError::AuthSize => write!(f, "the value of authorizationSizeis out of range or the number of octets in the Authorization Area is greater than required"),
            TpmFormatZeroError::AuthContext => write!(f, "use of an authorization session with a context command or another command that cannot have an authorization session"),
            TpmFormatZeroError::NvRange => write!(f, "NV offset+size is out of range"),
            TpmFormatZeroError::NvSize => write!(f, "Requested allocation size is larger than allowed"),
            TpmFormatZeroError::NvLocked => write!(f, "NV access locked"),
            TpmFormatZeroError::NvAuthorization => write!(f, "NV access authorization fails in command actions (this failure does not affect lockout.action)"),
            TpmFormatZeroError::NvUninitialized => write!(f, "an NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored"),
            TpmFormatZeroError::NvSpace => write!(f, "insufficient space for NV allocation"),
            TpmFormatZeroError::NvDefined => write!(f, "NV Index or persistent object already defined"),
            TpmFormatZeroError::BadContext => write!(f, "context in TPM2_ContextLoad() is not valid"),
            TpmFormatZeroError::CpHash => write!(f, "cpHash value already set or not correct for use"),
            TpmFormatZeroError::Parent => write!(f, "handle for parent is not a valid parent"),
            TpmFormatZeroError::NeedsTest => write!(f, "some function needs testing."),
            TpmFormatZeroError::NoResult => write!(f, "returned when an internal function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code."),
            TpmFormatZeroError::Sensitive => write!(f, "the sensitive area did not unmarshal correctly after decryption - this code is used in lieu of the other unmarshaling errors so that an attacker cannot determine where the unmarshaling error occurred"),
        }
    }
}
