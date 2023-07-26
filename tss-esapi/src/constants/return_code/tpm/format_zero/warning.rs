// // Copyright 2022 Contributors to the Parsec project.
// // SPDX-License-Identifier: Apache-2.0
use crate::constants::tss::{
    TPM2_RC_CANCELED, TPM2_RC_CONTEXT_GAP, TPM2_RC_LOCALITY, TPM2_RC_LOCKOUT, TPM2_RC_MEMORY,
    TPM2_RC_NV_RATE, TPM2_RC_NV_UNAVAILABLE, TPM2_RC_OBJECT_HANDLES, TPM2_RC_OBJECT_MEMORY,
    TPM2_RC_REFERENCE_H0, TPM2_RC_REFERENCE_H1, TPM2_RC_REFERENCE_H2, TPM2_RC_REFERENCE_H3,
    TPM2_RC_REFERENCE_H4, TPM2_RC_REFERENCE_H5, TPM2_RC_REFERENCE_H6, TPM2_RC_REFERENCE_S0,
    TPM2_RC_REFERENCE_S1, TPM2_RC_REFERENCE_S2, TPM2_RC_REFERENCE_S3, TPM2_RC_REFERENCE_S4,
    TPM2_RC_REFERENCE_S5, TPM2_RC_REFERENCE_S6, TPM2_RC_RETRY, TPM2_RC_SESSION_HANDLES,
    TPM2_RC_SESSION_MEMORY, TPM2_RC_TESTING, TPM2_RC_WARN, TPM2_RC_YIELDED,
};

use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing TPM format zero warning.
///
/// # Details
///
/// These are the values from the specification without
/// the indicator that indicates that it is a TPM format
/// zero warning (i.e. [TPM2_RC_WARN]).
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TpmFormatZeroWarning {
    ContextGap = (TPM2_RC_CONTEXT_GAP - TPM2_RC_WARN) as u8,
    ObjectMemory = (TPM2_RC_OBJECT_MEMORY - TPM2_RC_WARN) as u8,
    SessionMemory = (TPM2_RC_SESSION_MEMORY - TPM2_RC_WARN) as u8,
    Memory = (TPM2_RC_MEMORY - TPM2_RC_WARN) as u8,
    SessionHandles = (TPM2_RC_SESSION_HANDLES - TPM2_RC_WARN) as u8,
    ObjectHandles = (TPM2_RC_OBJECT_HANDLES - TPM2_RC_WARN) as u8,
    Locality = (TPM2_RC_LOCALITY - TPM2_RC_WARN) as u8,
    Yielded = (TPM2_RC_YIELDED - TPM2_RC_WARN) as u8,
    Canceled = (TPM2_RC_CANCELED - TPM2_RC_WARN) as u8,
    Testing = (TPM2_RC_TESTING - TPM2_RC_WARN) as u8,
    ReferenceH0 = (TPM2_RC_REFERENCE_H0 - TPM2_RC_WARN) as u8,
    ReferenceH1 = (TPM2_RC_REFERENCE_H1 - TPM2_RC_WARN) as u8,
    ReferenceH2 = (TPM2_RC_REFERENCE_H2 - TPM2_RC_WARN) as u8,
    ReferenceH3 = (TPM2_RC_REFERENCE_H3 - TPM2_RC_WARN) as u8,
    ReferenceH4 = (TPM2_RC_REFERENCE_H4 - TPM2_RC_WARN) as u8,
    ReferenceH5 = (TPM2_RC_REFERENCE_H5 - TPM2_RC_WARN) as u8,
    ReferenceH6 = (TPM2_RC_REFERENCE_H6 - TPM2_RC_WARN) as u8,
    ReferenceS0 = (TPM2_RC_REFERENCE_S0 - TPM2_RC_WARN) as u8,
    ReferenceS1 = (TPM2_RC_REFERENCE_S1 - TPM2_RC_WARN) as u8,
    ReferenceS2 = (TPM2_RC_REFERENCE_S2 - TPM2_RC_WARN) as u8,
    ReferenceS3 = (TPM2_RC_REFERENCE_S3 - TPM2_RC_WARN) as u8,
    ReferenceS4 = (TPM2_RC_REFERENCE_S4 - TPM2_RC_WARN) as u8,
    ReferenceS5 = (TPM2_RC_REFERENCE_S5 - TPM2_RC_WARN) as u8,
    ReferenceS6 = (TPM2_RC_REFERENCE_S6 - TPM2_RC_WARN) as u8,
    NvRate = (TPM2_RC_NV_RATE - TPM2_RC_WARN) as u8,
    Lockout = (TPM2_RC_LOCKOUT - TPM2_RC_WARN) as u8,
    Retry = (TPM2_RC_RETRY - TPM2_RC_WARN) as u8,
    NvUnavailable = (TPM2_RC_NV_UNAVAILABLE - TPM2_RC_WARN) as u8,
}

impl TryFrom<u8> for TpmFormatZeroWarning {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self> {
        TpmFormatZeroWarning::from_u8(value).ok_or_else(|| {
            error!(
                "Value 0x{:02X} is not a valid TPM format zero warning.",
                value
            );
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<TpmFormatZeroWarning> for u8 {
    fn from(value: TpmFormatZeroWarning) -> u8 {
        // This is safe because the values are well defined.
        value.to_u8().unwrap()
    }
}
