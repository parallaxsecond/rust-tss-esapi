// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    Error, WrapperErrorKind,
    constants::{
        ClockAdjust,
        tss::{
            TPM2_CLOCK_COARSE_FASTER, TPM2_CLOCK_COARSE_SLOWER, TPM2_CLOCK_FINE_FASTER,
            TPM2_CLOCK_FINE_SLOWER, TPM2_CLOCK_MEDIUM_FASTER, TPM2_CLOCK_MEDIUM_SLOWER,
            TPM2_CLOCK_NO_CHANGE,
        },
    },
    tss2_esys::TPM2_CLOCK_ADJUST,
};

#[test]
fn test_valid_conversions() {
    let test_cases = [
        (ClockAdjust::CoarseSlower, TPM2_CLOCK_COARSE_SLOWER),
        (ClockAdjust::MediumSlower, TPM2_CLOCK_MEDIUM_SLOWER),
        (ClockAdjust::FineSlower, TPM2_CLOCK_FINE_SLOWER),
        (ClockAdjust::NoChange, TPM2_CLOCK_NO_CHANGE),
        (ClockAdjust::FineFaster, TPM2_CLOCK_FINE_FASTER),
        (ClockAdjust::MediumFaster, TPM2_CLOCK_MEDIUM_FASTER),
        (ClockAdjust::CoarseFaster, TPM2_CLOCK_COARSE_FASTER),
    ];

    for (clock_adjust, expected_tpm_value) in test_cases {
        assert_eq!(
            expected_tpm_value,
            TPM2_CLOCK_ADJUST::from(clock_adjust),
            "ClockAdjust did not convert to the expected TPM value"
        );
        assert_eq!(
            clock_adjust,
            ClockAdjust::try_from(expected_tpm_value)
                .expect("Failed to convert TPM value to ClockAdjust"),
            "TPM value did not convert to the expected ClockAdjust"
        );
    }
}

#[test]
fn test_invalid_conversions() {
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        ClockAdjust::try_from(4),
        "Conversion of invalid value did not result in expected error"
    );
}
