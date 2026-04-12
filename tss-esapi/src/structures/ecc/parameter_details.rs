// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result,
    interface_types::ecc::EccCurve,
    structures::{EccParameter, EccScheme, KeyDerivationFunctionScheme},
    tss2_esys::TPMS_ALGORITHM_DETAIL_ECC,
};
use std::convert::{TryFrom, TryInto};

/// Detailed information about an ECC curve.
///
/// # Details
/// This corresponds to `TPMS_ALGORITHM_DETAIL_ECC`.
#[derive(Debug, Clone)]
pub struct EccParameterDetails {
    curve_id: EccCurve,
    key_size: u16,
    kdf: KeyDerivationFunctionScheme,
    sign: EccScheme,
    p: EccParameter,
    a: EccParameter,
    b: EccParameter,
    g_x: EccParameter,
    g_y: EccParameter,
    n: EccParameter,
    h: EccParameter,
}

impl EccParameterDetails {
    /// Returns the curve ID.
    pub const fn curve_id(&self) -> EccCurve {
        self.curve_id
    }

    /// Returns the key size in bits.
    pub const fn key_size(&self) -> u16 {
        self.key_size
    }

    /// Returns the key derivation function scheme.
    pub const fn kdf(&self) -> &KeyDerivationFunctionScheme {
        &self.kdf
    }

    /// Returns the signing scheme.
    pub const fn sign(&self) -> &EccScheme {
        &self.sign
    }

    /// Returns the prime modulus p.
    pub const fn p(&self) -> &EccParameter {
        &self.p
    }

    /// Returns the curve coefficient a.
    pub const fn a(&self) -> &EccParameter {
        &self.a
    }

    /// Returns the curve coefficient b.
    pub const fn b(&self) -> &EccParameter {
        &self.b
    }

    /// Returns the x-coordinate of the base point G.
    pub const fn g_x(&self) -> &EccParameter {
        &self.g_x
    }

    /// Returns the y-coordinate of the base point G.
    pub const fn g_y(&self) -> &EccParameter {
        &self.g_y
    }

    /// Returns the order of the base point n.
    pub const fn n(&self) -> &EccParameter {
        &self.n
    }

    /// Returns the cofactor h.
    pub const fn h(&self) -> &EccParameter {
        &self.h
    }
}

impl TryFrom<TPMS_ALGORITHM_DETAIL_ECC> for EccParameterDetails {
    type Error = Error;

    fn try_from(details: TPMS_ALGORITHM_DETAIL_ECC) -> Result<Self> {
        Ok(EccParameterDetails {
            curve_id: EccCurve::try_from(details.curveID)?,
            key_size: details.keySize,
            kdf: details.kdf.try_into()?,
            sign: details.sign.try_into()?,
            p: details.p.try_into()?,
            a: details.a.try_into()?,
            b: details.b.try_into()?,
            g_x: details.gX.try_into()?,
            g_y: details.gY.try_into()?,
            n: details.n.try_into()?,
            h: details.h.try_into()?,
        })
    }
}
