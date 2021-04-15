// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPMS_CLOCK_INFO;
use crate::{Error, Result, WrapperErrorKind};
use std::convert::TryFrom;

/// Information related to the internal temporal
/// state of the TPM.
///
/// # Details
/// Corresponds to `TPMS_CLOCK_INFO`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockInfo {
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
}

impl ClockInfo {
    pub fn clock(&self) -> u64 {
        self.clock
    }

    pub fn reset_count(&self) -> u32 {
        self.reset_count
    }

    pub fn restart_count(&self) -> u32 {
        self.restart_count
    }

    pub fn safe(&self) -> bool {
        self.safe
    }
}

impl TryFrom<TPMS_CLOCK_INFO> for ClockInfo {
    type Error = Error;

    fn try_from(tss: TPMS_CLOCK_INFO) -> Result<Self> {
        let safe = match tss.safe {
            0 => false,
            1 => true,
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        };

        Ok(ClockInfo {
            clock: tss.clock,
            reset_count: tss.resetCount,
            restart_count: tss.restartCount,
            safe,
        })
    }
}

impl From<ClockInfo> for TPMS_CLOCK_INFO {
    fn from(native: ClockInfo) -> Self {
        TPMS_CLOCK_INFO {
            clock: native.clock,
            resetCount: native.reset_count,
            restartCount: native.restart_count,
            safe: if native.safe { 1 } else { 0 },
        }
    }
}
