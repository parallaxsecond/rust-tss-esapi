// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result, WrapperErrorKind,
    constants::tss::{
        TPM2_CLOCK_COARSE_FASTER, TPM2_CLOCK_COARSE_SLOWER, TPM2_CLOCK_FINE_FASTER,
        TPM2_CLOCK_FINE_SLOWER, TPM2_CLOCK_MEDIUM_FASTER, TPM2_CLOCK_MEDIUM_SLOWER,
        TPM2_CLOCK_NO_CHANGE,
    },
    tss2_esys::TPM2_CLOCK_ADJUST,
};
use log::error;
use std::convert::TryFrom;

/// Clock-rate adjustment for TPM clock updates.
///
/// # Details
/// This corresponds to the `TPM2_CLOCK_ADJUST` type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClockAdjust {
    /// Slow the clock update rate by one coarse adjustment step.
    CoarseSlower,
    /// Slow the clock update rate by one medium adjustment step.
    MediumSlower,
    /// Slow the clock update rate by one fine adjustment step.
    FineSlower,
    /// Do not change the clock update rate.
    NoChange,
    /// Speed the clock update rate by one fine adjustment step.
    FineFaster,
    /// Speed the clock update rate by one medium adjustment step.
    MediumFaster,
    /// Speed the clock update rate by one coarse adjustment step.
    CoarseFaster,
}

impl From<ClockAdjust> for TPM2_CLOCK_ADJUST {
    fn from(clock_adjust: ClockAdjust) -> Self {
        match clock_adjust {
            ClockAdjust::CoarseSlower => TPM2_CLOCK_COARSE_SLOWER,
            ClockAdjust::MediumSlower => TPM2_CLOCK_MEDIUM_SLOWER,
            ClockAdjust::FineSlower => TPM2_CLOCK_FINE_SLOWER,
            ClockAdjust::NoChange => TPM2_CLOCK_NO_CHANGE,
            ClockAdjust::FineFaster => TPM2_CLOCK_FINE_FASTER,
            ClockAdjust::MediumFaster => TPM2_CLOCK_MEDIUM_FASTER,
            ClockAdjust::CoarseFaster => TPM2_CLOCK_COARSE_FASTER,
        }
    }
}

impl TryFrom<TPM2_CLOCK_ADJUST> for ClockAdjust {
    type Error = Error;

    fn try_from(tpm2_clock_adjust: TPM2_CLOCK_ADJUST) -> Result<Self> {
        match tpm2_clock_adjust {
            TPM2_CLOCK_COARSE_SLOWER => Ok(ClockAdjust::CoarseSlower),
            TPM2_CLOCK_MEDIUM_SLOWER => Ok(ClockAdjust::MediumSlower),
            TPM2_CLOCK_FINE_SLOWER => Ok(ClockAdjust::FineSlower),
            TPM2_CLOCK_NO_CHANGE => Ok(ClockAdjust::NoChange),
            TPM2_CLOCK_FINE_FASTER => Ok(ClockAdjust::FineFaster),
            TPM2_CLOCK_MEDIUM_FASTER => Ok(ClockAdjust::MediumFaster),
            TPM2_CLOCK_COARSE_FASTER => Ok(ClockAdjust::CoarseFaster),
            _ => {
                error!("Invalid TPM2_CLOCK_ADJUST value: {}", tpm2_clock_adjust);
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
