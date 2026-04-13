// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result, WrapperErrorKind,
    constants::tss::{
        TPM2_EO_BITCLEAR, TPM2_EO_BITSET, TPM2_EO_EQ, TPM2_EO_NEQ, TPM2_EO_SIGNED_GE,
        TPM2_EO_SIGNED_GT, TPM2_EO_SIGNED_LE, TPM2_EO_SIGNED_LT, TPM2_EO_UNSIGNED_GE,
        TPM2_EO_UNSIGNED_GT, TPM2_EO_UNSIGNED_LE, TPM2_EO_UNSIGNED_LT,
    },
    tss2_esys::TPM2_EO,
};
use log::error;
use std::convert::TryFrom;

/// Arithmetic comparison operation for policy evaluation.
///
/// # Details
/// This corresponds to the `TPM2_EO` type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ArithmeticComparison {
    /// A == B
    Eq,
    /// A != B
    Neq,
    /// A > B (signed)
    SignedGt,
    /// A > B (unsigned)
    UnsignedGt,
    /// A < B (signed)
    SignedLt,
    /// A < B (unsigned)
    UnsignedLt,
    /// A >= B (signed)
    SignedGe,
    /// A >= B (unsigned)
    UnsignedGe,
    /// A <= B (signed)
    SignedLe,
    /// A <= B (unsigned)
    UnsignedLe,
    /// All bits SET in B are SET in A
    BitSet,
    /// All bits SET in B are CLEAR in A
    BitClear,
}

impl From<ArithmeticComparison> for TPM2_EO {
    fn from(arithmetic_comparison: ArithmeticComparison) -> Self {
        match arithmetic_comparison {
            ArithmeticComparison::Eq => TPM2_EO_EQ,
            ArithmeticComparison::Neq => TPM2_EO_NEQ,
            ArithmeticComparison::SignedGt => TPM2_EO_SIGNED_GT,
            ArithmeticComparison::UnsignedGt => TPM2_EO_UNSIGNED_GT,
            ArithmeticComparison::SignedLt => TPM2_EO_SIGNED_LT,
            ArithmeticComparison::UnsignedLt => TPM2_EO_UNSIGNED_LT,
            ArithmeticComparison::SignedGe => TPM2_EO_SIGNED_GE,
            ArithmeticComparison::UnsignedGe => TPM2_EO_UNSIGNED_GE,
            ArithmeticComparison::SignedLe => TPM2_EO_SIGNED_LE,
            ArithmeticComparison::UnsignedLe => TPM2_EO_UNSIGNED_LE,
            ArithmeticComparison::BitSet => TPM2_EO_BITSET,
            ArithmeticComparison::BitClear => TPM2_EO_BITCLEAR,
        }
    }
}

impl TryFrom<TPM2_EO> for ArithmeticComparison {
    type Error = Error;

    fn try_from(tpm2_eo: TPM2_EO) -> Result<Self> {
        match tpm2_eo {
            TPM2_EO_EQ => Ok(ArithmeticComparison::Eq),
            TPM2_EO_NEQ => Ok(ArithmeticComparison::Neq),
            TPM2_EO_SIGNED_GT => Ok(ArithmeticComparison::SignedGt),
            TPM2_EO_UNSIGNED_GT => Ok(ArithmeticComparison::UnsignedGt),
            TPM2_EO_SIGNED_LT => Ok(ArithmeticComparison::SignedLt),
            TPM2_EO_UNSIGNED_LT => Ok(ArithmeticComparison::UnsignedLt),
            TPM2_EO_SIGNED_GE => Ok(ArithmeticComparison::SignedGe),
            TPM2_EO_UNSIGNED_GE => Ok(ArithmeticComparison::UnsignedGe),
            TPM2_EO_SIGNED_LE => Ok(ArithmeticComparison::SignedLe),
            TPM2_EO_UNSIGNED_LE => Ok(ArithmeticComparison::UnsignedLe),
            TPM2_EO_BITSET => Ok(ArithmeticComparison::BitSet),
            TPM2_EO_BITCLEAR => Ok(ArithmeticComparison::BitClear),
            _ => {
                error!("Invalid TPM2_EO value: {}", tpm2_eo);
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
