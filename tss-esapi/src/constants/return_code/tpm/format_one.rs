// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::tss::{
    TPM2_RC_ASYMMETRIC, TPM2_RC_ATTRIBUTES, TPM2_RC_AUTH_FAIL, TPM2_RC_BAD_AUTH, TPM2_RC_BINDING,
    TPM2_RC_CURVE, TPM2_RC_ECC_POINT, TPM2_RC_EXPIRED, TPM2_RC_FMT1, TPM2_RC_HANDLE, TPM2_RC_HASH,
    TPM2_RC_HIERARCHY, TPM2_RC_INSUFFICIENT, TPM2_RC_INTEGRITY, TPM2_RC_KDF, TPM2_RC_KEY,
    TPM2_RC_KEY_SIZE, TPM2_RC_MGF, TPM2_RC_MODE, TPM2_RC_NONCE, TPM2_RC_POLICY_CC,
    TPM2_RC_POLICY_FAIL, TPM2_RC_PP, TPM2_RC_RANGE, TPM2_RC_RESERVED_BITS, TPM2_RC_SCHEME,
    TPM2_RC_SELECTOR, TPM2_RC_SIGNATURE, TPM2_RC_SIZE, TPM2_RC_SYMMETRIC, TPM2_RC_TAG,
    TPM2_RC_TICKET, TPM2_RC_TYPE, TPM2_RC_VALUE,
};

use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing TPM format one error.
///
/// # Details
///
/// These are the values from the specification without
/// the indicator that indicates that it is a TPM format
/// one error (i.e. [TPM2_RC_FMT1]) and without any information
/// regarding what parameter, session or handle that was indicated
/// by the response code from the TPM.
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TpmFormatOneError {
    Asymmetric = (TPM2_RC_ASYMMETRIC - TPM2_RC_FMT1) as u8,
    Attributes = (TPM2_RC_ATTRIBUTES - TPM2_RC_FMT1) as u8,
    Hash = (TPM2_RC_HASH - TPM2_RC_FMT1) as u8,
    Value = (TPM2_RC_VALUE - TPM2_RC_FMT1) as u8,
    Hierarchy = (TPM2_RC_HIERARCHY - TPM2_RC_FMT1) as u8,
    KeySize = (TPM2_RC_KEY_SIZE - TPM2_RC_FMT1) as u8,
    Mgf = (TPM2_RC_MGF - TPM2_RC_FMT1) as u8,
    Mode = (TPM2_RC_MODE - TPM2_RC_FMT1) as u8,
    Type = (TPM2_RC_TYPE - TPM2_RC_FMT1) as u8,
    Handle = (TPM2_RC_HANDLE - TPM2_RC_FMT1) as u8,
    Kdf = (TPM2_RC_KDF - TPM2_RC_FMT1) as u8,
    Range = (TPM2_RC_RANGE - TPM2_RC_FMT1) as u8,
    AuthFail = (TPM2_RC_AUTH_FAIL - TPM2_RC_FMT1) as u8,
    Nonce = (TPM2_RC_NONCE - TPM2_RC_FMT1) as u8,
    Pp = (TPM2_RC_PP - TPM2_RC_FMT1) as u8,
    Scheme = (TPM2_RC_SCHEME - TPM2_RC_FMT1) as u8,
    Size = (TPM2_RC_SIZE - TPM2_RC_FMT1) as u8,
    Symmetric = (TPM2_RC_SYMMETRIC - TPM2_RC_FMT1) as u8,
    Tag = (TPM2_RC_TAG - TPM2_RC_FMT1) as u8,
    Selector = (TPM2_RC_SELECTOR - TPM2_RC_FMT1) as u8,
    Insufficient = (TPM2_RC_INSUFFICIENT - TPM2_RC_FMT1) as u8,
    Signature = (TPM2_RC_SIGNATURE - TPM2_RC_FMT1) as u8,
    Key = (TPM2_RC_KEY - TPM2_RC_FMT1) as u8,
    PolicyFail = (TPM2_RC_POLICY_FAIL - TPM2_RC_FMT1) as u8,
    Integrity = (TPM2_RC_INTEGRITY - TPM2_RC_FMT1) as u8,
    Ticket = (TPM2_RC_TICKET - TPM2_RC_FMT1) as u8,
    ReservedBits = (TPM2_RC_RESERVED_BITS - TPM2_RC_FMT1) as u8,
    BadAuth = (TPM2_RC_BAD_AUTH - TPM2_RC_FMT1) as u8,
    Expired = (TPM2_RC_EXPIRED - TPM2_RC_FMT1) as u8,
    PolicyCc = (TPM2_RC_POLICY_CC - TPM2_RC_FMT1) as u8,
    Binding = (TPM2_RC_BINDING - TPM2_RC_FMT1) as u8,
    Curve = (TPM2_RC_CURVE - TPM2_RC_FMT1) as u8,
    EccPoint = (TPM2_RC_ECC_POINT - TPM2_RC_FMT1) as u8,
}

impl TryFrom<u8> for TpmFormatOneError {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        TpmFormatOneError::from_u8(value).ok_or_else(|| {
            error!("Value 0x{:02X} is not a valid TPM format one error", value);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<TpmFormatOneError> for u8 {
    fn from(tpm_format_one_error: TpmFormatOneError) -> Self {
        // This is safe because the values are well defined.
        tpm_format_one_error.to_u8().unwrap()
    }
}
