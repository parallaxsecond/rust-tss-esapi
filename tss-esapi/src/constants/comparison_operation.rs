// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! The comparison operators used by `TPM2_PolicyNV`.

use crate::{Error, Result, WrapperErrorKind, tss2_esys::TPM2_EO};
use log::error;
use std::convert::TryFrom;

/// Enum representing the comparison operations (TPM2_EO) of the TPM 2.0
/// specification, used to compare an NV Index's contents with an operand.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum ComparisonOperation {
    /// A = B
    Eq = 0x0000,
    /// A != B
    Neq = 0x0001,
    /// A > B, signed
    SignedGt = 0x0002,
    /// A > B, unsigned
    UnsignedGt = 0x0003,
    /// A < B, signed
    SignedLt = 0x0004,
    /// A < B, unsigned
    UnsignedLt = 0x0005,
    /// A >= B, signed
    SignedGe = 0x0006,
    /// A >= B, unsigned
    UnsignedGe = 0x0007,
    /// A <= B, signed
    SignedLe = 0x0008,
    /// A <= B, unsigned
    UnsignedLe = 0x0009,
    /// All bits set in B are set in A
    BitSet = 0x000A,
    /// All bits set in B are clear in A
    BitClear = 0x000B,
}

impl From<ComparisonOperation> for TPM2_EO {
    fn from(operation: ComparisonOperation) -> TPM2_EO {
        operation as TPM2_EO
    }
}

impl TryFrom<TPM2_EO> for ComparisonOperation {
    type Error = Error;

    fn try_from(tss_comparison_operation: TPM2_EO) -> Result<ComparisonOperation> {
        match tss_comparison_operation {
            0x0000 => Ok(ComparisonOperation::Eq),
            0x0001 => Ok(ComparisonOperation::Neq),
            0x0002 => Ok(ComparisonOperation::SignedGt),
            0x0003 => Ok(ComparisonOperation::UnsignedGt),
            0x0004 => Ok(ComparisonOperation::SignedLt),
            0x0005 => Ok(ComparisonOperation::UnsignedLt),
            0x0006 => Ok(ComparisonOperation::SignedGe),
            0x0007 => Ok(ComparisonOperation::UnsignedGe),
            0x0008 => Ok(ComparisonOperation::SignedLe),
            0x0009 => Ok(ComparisonOperation::UnsignedLe),
            0x000A => Ok(ComparisonOperation::BitSet),
            0x000B => Ok(ComparisonOperation::BitClear),
            _ => {
                error!("Value  is not a valid ComparisonOperation");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
