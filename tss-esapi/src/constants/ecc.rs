// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_ECC_BN_P256, TPM2_ECC_BN_P638, TPM2_ECC_NIST_P192, TPM2_ECC_NIST_P224,
        TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384, TPM2_ECC_NIST_P521, TPM2_ECC_SM2_P256,
    },
    tss2_esys::TPM2_ECC_CURVE,
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// Enum that contains the constants for the
/// implemented elliptic curves.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ImplementedEllipticCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl From<ImplementedEllipticCurve> for TPM2_ECC_CURVE {
    fn from(curve: ImplementedEllipticCurve) -> Self {
        match curve {
            ImplementedEllipticCurve::NistP192 => TPM2_ECC_NIST_P192,
            ImplementedEllipticCurve::NistP224 => TPM2_ECC_NIST_P224,
            ImplementedEllipticCurve::NistP256 => TPM2_ECC_NIST_P256,
            ImplementedEllipticCurve::NistP384 => TPM2_ECC_NIST_P384,
            ImplementedEllipticCurve::NistP521 => TPM2_ECC_NIST_P521,
            ImplementedEllipticCurve::BnP256 => TPM2_ECC_BN_P256,
            ImplementedEllipticCurve::BnP638 => TPM2_ECC_BN_P638,
            ImplementedEllipticCurve::Sm2P256 => TPM2_ECC_SM2_P256,
        }
    }
}

impl TryFrom<TPM2_ECC_CURVE> for ImplementedEllipticCurve {
    type Error = Error;

    fn try_from(curve: TPM2_ECC_CURVE) -> Result<Self> {
        match curve {
            TPM2_ECC_NIST_P192 => Ok(ImplementedEllipticCurve::NistP192),
            TPM2_ECC_NIST_P224 => Ok(ImplementedEllipticCurve::NistP224),
            TPM2_ECC_NIST_P256 => Ok(ImplementedEllipticCurve::NistP256),
            TPM2_ECC_NIST_P384 => Ok(ImplementedEllipticCurve::NistP384),
            TPM2_ECC_NIST_P521 => Ok(ImplementedEllipticCurve::NistP521),
            TPM2_ECC_BN_P256 => Ok(ImplementedEllipticCurve::BnP256),
            TPM2_ECC_BN_P638 => Ok(ImplementedEllipticCurve::BnP638),
            TPM2_ECC_SM2_P256 => Ok(ImplementedEllipticCurve::Sm2P256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
