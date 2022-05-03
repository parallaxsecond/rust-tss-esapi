// // Copyright 2022 Contributors to the Parsec project.
// // SPDX-License-Identifier: Apache-2.0
use crate::constants::tss::{
    TPM2_RC_AUTHSIZE, TPM2_RC_AUTH_CONTEXT, TPM2_RC_AUTH_MISSING, TPM2_RC_AUTH_TYPE,
    TPM2_RC_AUTH_UNAVAILABLE, TPM2_RC_BAD_CONTEXT, TPM2_RC_COMMAND_CODE, TPM2_RC_COMMAND_SIZE,
    TPM2_RC_CPHASH, TPM2_RC_DISABLED, TPM2_RC_EXCLUSIVE, TPM2_RC_FAILURE, TPM2_RC_HMAC,
    TPM2_RC_INITIALIZE, TPM2_RC_NEEDS_TEST, TPM2_RC_NO_RESULT, TPM2_RC_NV_AUTHORIZATION,
    TPM2_RC_NV_DEFINED, TPM2_RC_NV_LOCKED, TPM2_RC_NV_RANGE, TPM2_RC_NV_SIZE, TPM2_RC_NV_SPACE,
    TPM2_RC_NV_UNINITIALIZED, TPM2_RC_PARENT, TPM2_RC_PCR, TPM2_RC_PCR_CHANGED, TPM2_RC_POLICY,
    TPM2_RC_PRIVATE, TPM2_RC_REBOOT, TPM2_RC_SENSITIVE, TPM2_RC_SEQUENCE,
    TPM2_RC_TOO_MANY_CONTEXTS, TPM2_RC_UNBALANCED, TPM2_RC_UPGRADE, TPM2_RC_VER1,
};

use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing TPM format zero error.
///
/// # Details
///
/// These are the values from the specification without
/// the indicator that indicates that it is a TPM format
/// zero error (i.e. [TPM2_RC_VER1]).
///
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TpmFormatZeroError {
    Initialize = (TPM2_RC_INITIALIZE - TPM2_RC_VER1) as u8,
    Failure = (TPM2_RC_FAILURE - TPM2_RC_VER1) as u8,
    Sequence = (TPM2_RC_SEQUENCE - TPM2_RC_VER1) as u8,
    Private = (TPM2_RC_PRIVATE - TPM2_RC_VER1) as u8,
    Hmac = (TPM2_RC_HMAC - TPM2_RC_VER1) as u8,
    Disabled = (TPM2_RC_DISABLED - TPM2_RC_VER1) as u8,
    Exclusive = (TPM2_RC_EXCLUSIVE - TPM2_RC_VER1) as u8,
    AuthType = (TPM2_RC_AUTH_TYPE - TPM2_RC_VER1) as u8,
    AuthMissing = (TPM2_RC_AUTH_MISSING - TPM2_RC_VER1) as u8,
    Policy = (TPM2_RC_POLICY - TPM2_RC_VER1) as u8,
    Pcr = (TPM2_RC_PCR - TPM2_RC_VER1) as u8,
    PcrChanged = (TPM2_RC_PCR_CHANGED - TPM2_RC_VER1) as u8,
    Upgrade = (TPM2_RC_UPGRADE - TPM2_RC_VER1) as u8,
    TooManyContexts = (TPM2_RC_TOO_MANY_CONTEXTS - TPM2_RC_VER1) as u8,
    AuthUnavailable = (TPM2_RC_AUTH_UNAVAILABLE - TPM2_RC_VER1) as u8,
    Reboot = (TPM2_RC_REBOOT - TPM2_RC_VER1) as u8,
    Unbalanced = (TPM2_RC_UNBALANCED - TPM2_RC_VER1) as u8,
    CommandSize = (TPM2_RC_COMMAND_SIZE - TPM2_RC_VER1) as u8,
    CommandCode = (TPM2_RC_COMMAND_CODE - TPM2_RC_VER1) as u8,
    AuthSize = (TPM2_RC_AUTHSIZE - TPM2_RC_VER1) as u8,
    AuthContext = (TPM2_RC_AUTH_CONTEXT - TPM2_RC_VER1) as u8,
    NvRange = (TPM2_RC_NV_RANGE - TPM2_RC_VER1) as u8,
    NvSize = (TPM2_RC_NV_SIZE - TPM2_RC_VER1) as u8,
    NvLocked = (TPM2_RC_NV_LOCKED - TPM2_RC_VER1) as u8,
    NvAuthorization = (TPM2_RC_NV_AUTHORIZATION - TPM2_RC_VER1) as u8,
    NvUninitialized = (TPM2_RC_NV_UNINITIALIZED - TPM2_RC_VER1) as u8,
    NvSpace = (TPM2_RC_NV_SPACE - TPM2_RC_VER1) as u8,
    NvDefined = (TPM2_RC_NV_DEFINED - TPM2_RC_VER1) as u8,
    BadContext = (TPM2_RC_BAD_CONTEXT - TPM2_RC_VER1) as u8,
    CpHash = (TPM2_RC_CPHASH - TPM2_RC_VER1) as u8,
    Parent = (TPM2_RC_PARENT - TPM2_RC_VER1) as u8,
    NeedsTest = (TPM2_RC_NEEDS_TEST - TPM2_RC_VER1) as u8,
    NoResult = (TPM2_RC_NO_RESULT - TPM2_RC_VER1) as u8,
    Sensitive = (TPM2_RC_SENSITIVE - TPM2_RC_VER1) as u8,
}

impl TryFrom<u8> for TpmFormatZeroError {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        TpmFormatZeroError::from_u8(value).ok_or_else(|| {
            error!(
                "Value 0x{:02X} is not a valid TPM format zero error.",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<TpmFormatZeroError> for u8 {
    fn from(tpm_format_zeror_error: TpmFormatZeroError) -> Self {
        // This is safe because the values are well defined.
        tpm_format_zeror_error.to_u8().unwrap()
    }
}
