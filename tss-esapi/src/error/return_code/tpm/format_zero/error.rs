// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::return_code::TpmFormatZeroError, Error, Result};
use std::convert::TryFrom;

/// Type representing the TPM format zero error
/// response code.
///
/// # Details
/// The error messages are short forms of the descriptions given in the specification
/// that describes return codes (see the
/// [Part 2, Structures](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part2_Structures_pub.pdf)).
/// Sometimes these descriptions refers to fields within the structures described in the specification. When
/// a message contains such a description then the name of the of the field is surrounded with backticks
/// (e.g. `authValue`).
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
            TpmFormatZeroError::Initialize => write!(f, "TPM not initialized by TPM2_Startup or already initialized."),
            TpmFormatZeroError::Failure => write!(f, "Commands not accepted because of a TPM failure."),
            TpmFormatZeroError::Sequence => write!(f, "Improper use of a sequence handle."),
            TpmFormatZeroError::Private => write!(f, "Not currently used."),
            TpmFormatZeroError::Hmac => write!(f, "Not currently used."),
            TpmFormatZeroError::Disabled => write!(f, "The command is disabled."),
            TpmFormatZeroError::Exclusive => write!(f, "Command failed because audit sequence required exclusivity."),
            TpmFormatZeroError::AuthType => write!(f, "Authorization handle is not correct for command."),
            TpmFormatZeroError::AuthMissing => write!(f, "Command requires an authorization session for handle and it is not present."),
            TpmFormatZeroError::Policy => write!(f, "Policy failure in math operation or an invalid `authPolicy` value."),
            TpmFormatZeroError::Pcr => write!(f, "PCR check fail."),
            TpmFormatZeroError::PcrChanged => write!(f, "PCR have changed since checked."),
            TpmFormatZeroError::Upgrade => write!(f, "For all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode."),
            TpmFormatZeroError::TooManyContexts => write!(f, "Context ID counter is at maximum."),
            TpmFormatZeroError::AuthUnavailable => write!(f, "`authValue` or `authPolicy` is not available for selected entity."),
            TpmFormatZeroError::Reboot => write!(f, "A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation."),
            TpmFormatZeroError::Unbalanced => write!(f, "The protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm."),
            TpmFormatZeroError::CommandSize => write!(f, "Command `commandSize` value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header."),
            TpmFormatZeroError::CommandCode => write!(f, "Command code not supported."),
            TpmFormatZeroError::AuthSize => write!(f, "The value of `authorizationSize` is out of range or the number of octets in the authorization area is greater than required."),
            TpmFormatZeroError::AuthContext => write!(f, "Use of an authorization session with a context command or another command that cannot have an authorization session."),
            TpmFormatZeroError::NvRange => write!(f, "NV offset+size is out of range."),
            TpmFormatZeroError::NvSize => write!(f, "Requested allocation size is larger than allowed."),
            TpmFormatZeroError::NvLocked => write!(f, "NV access locked."),
            TpmFormatZeroError::NvAuthorization => write!(f, "NV access authorization fails in command actions."),
            TpmFormatZeroError::NvUninitialized => write!(f, "An NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored."),
            TpmFormatZeroError::NvSpace => write!(f, "Insufficient space for NV allocation."),
            TpmFormatZeroError::NvDefined => write!(f, "NV Index or persistent object already defined."),
            TpmFormatZeroError::BadContext => write!(f, "Context in TPM2_ContextLoad() is not valid."),
            TpmFormatZeroError::CpHash => write!(f, "`cpHash` value already set or not correct for use."),
            TpmFormatZeroError::Parent => write!(f, "Handle for parent is not a valid parent."),
            TpmFormatZeroError::NeedsTest => write!(f, "Function needs testing."),
            TpmFormatZeroError::NoResult => write!(f, "Function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code."),
            TpmFormatZeroError::Sensitive => write!(f, "The sensitive area did not unmarshal correctly after decryption."),
        }
    }
}
