// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{constants::ImplementedEllipticCurve, tss2_esys::TPMI_ECC_CURVE, Error, Result};
use std::convert::TryFrom;
/// Enum containing the implemented ECC curves
///
/// # Details
/// This corresponds to TPMI_ECC_CURVE
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EllipticCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl From<EllipticCurve> for ImplementedEllipticCurve {
    fn from(curve: EllipticCurve) -> Self {
        match curve {
            EllipticCurve::NistP192 => ImplementedEllipticCurve::NistP192,
            EllipticCurve::NistP224 => ImplementedEllipticCurve::NistP224,
            EllipticCurve::NistP256 => ImplementedEllipticCurve::NistP256,
            EllipticCurve::NistP384 => ImplementedEllipticCurve::NistP384,
            EllipticCurve::NistP521 => ImplementedEllipticCurve::NistP521,
            EllipticCurve::BnP256 => ImplementedEllipticCurve::BnP256,
            EllipticCurve::BnP638 => ImplementedEllipticCurve::BnP638,
            EllipticCurve::Sm2P256 => ImplementedEllipticCurve::Sm2P256,
        }
    }
}

impl From<ImplementedEllipticCurve> for EllipticCurve {
    fn from(implemented_curve: ImplementedEllipticCurve) -> Self {
        match implemented_curve {
            ImplementedEllipticCurve::NistP192 => EllipticCurve::NistP192,
            ImplementedEllipticCurve::NistP224 => EllipticCurve::NistP224,
            ImplementedEllipticCurve::NistP256 => EllipticCurve::NistP256,
            ImplementedEllipticCurve::NistP384 => EllipticCurve::NistP384,
            ImplementedEllipticCurve::NistP521 => EllipticCurve::NistP521,
            ImplementedEllipticCurve::BnP256 => EllipticCurve::BnP256,
            ImplementedEllipticCurve::BnP638 => EllipticCurve::BnP638,
            ImplementedEllipticCurve::Sm2P256 => EllipticCurve::Sm2P256,
        }
    }
}

impl From<EllipticCurve> for TPMI_ECC_CURVE {
    fn from(curve: EllipticCurve) -> Self {
        ImplementedEllipticCurve::from(curve).into()
    }
}

impl TryFrom<TPMI_ECC_CURVE> for EllipticCurve {
    type Error = Error;

    fn try_from(tpmi_ecc_curve: TPMI_ECC_CURVE) -> Result<Self> {
        Ok(EllipticCurve::from(ImplementedEllipticCurve::try_from(
            tpmi_ecc_curve,
        )?))
    }
}
