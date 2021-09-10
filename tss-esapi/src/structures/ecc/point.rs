// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{structures::EccParameter, tss2_esys::TPMS_ECC_POINT, Error, Result};
use std::convert::{TryFrom, TryInto};

/// Structure holding ecc point information
///
/// # Details
/// This corresponds to TPMS_ECC_POINT
#[derive(Debug, Clone)]
pub struct EccPoint {
    x: EccParameter,
    y: EccParameter,
}

impl EccPoint {
    /// Creates a new ecc point
    pub const fn new(x: EccParameter, y: EccParameter) -> Self {
        EccPoint { x, y }
    }

    /// Returns x value as an [EccParameter] reference.
    pub const fn x(&self) -> &EccParameter {
        &self.x
    }

    /// Returns y value as an [EccParameter] reference.
    pub const fn y(&self) -> &EccParameter {
        &self.y
    }
}

impl Default for EccPoint {
    fn default() -> Self {
        EccPoint::new(EccParameter::default(), EccParameter::default())
    }
}

impl From<EccPoint> for TPMS_ECC_POINT {
    fn from(ecc_point: EccPoint) -> Self {
        TPMS_ECC_POINT {
            x: ecc_point.x.into(),
            y: ecc_point.y.into(),
        }
    }
}

impl TryFrom<TPMS_ECC_POINT> for EccPoint {
    type Error = Error;

    fn try_from(tpms_ecc_point: TPMS_ECC_POINT) -> Result<Self> {
        Ok(EccPoint {
            x: tpms_ecc_point.x.try_into()?,
            y: tpms_ecc_point.y.try_into()?,
        })
    }
}
