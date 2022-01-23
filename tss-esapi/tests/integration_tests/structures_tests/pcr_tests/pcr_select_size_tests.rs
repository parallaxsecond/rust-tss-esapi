// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{structures::PcrSelectSize, Error, WrapperErrorKind};

macro_rules! test_valid_conversions {
    (PcrSelectSize::$expected:ident, $value:expr) => {
        let expected_u8 = $value;
        let expected_u32 = $value;
        let expected_usize = $value;

        assert_eq!(
            expected_u8,
            PcrSelectSize::$expected.as_u8(),
            "The PcrSelectSize as_u8() method for {} did not give the expected u8 value {}",
            stringify!(PcrSelectSize::$expected),
            expected_u8
        );

        assert_eq!(
            expected_u32,
            PcrSelectSize::$expected.as_u32(),
            "The PcrSelectSize as_u32() method for {} did not give the expected u32 value {}",
            stringify!(PcrSelectSize::$expected),
            expected_u32
        );

        assert_eq!(
            expected_usize,
            PcrSelectSize::$expected.as_usize(),
            "The PcrSelectSize as_usize() method for {} did not give the expected usize value {}",
            stringify!(PcrSelectSize::$expected),
            expected_usize
        );

        assert_eq!(
            PcrSelectSize::$expected,
            PcrSelectSize::try_parse_u8(expected_u8).expect(&format!(
                "try_parse_u8 failed to parse value {}",
                expected_u8
            )),
            "The u8 value {} did not get parsed as the expected {}",
            expected_u8,
            stringify!(PcrSelectSize::$expected),
        );

        assert_eq!(
            PcrSelectSize::$expected,
            PcrSelectSize::try_parse_u32(expected_u32).expect(&format!(
                "try_parse_u32 failed to parse value {}",
                expected_u32
            )),
            "The u32 value {} did not get parsed as the expected {}",
            expected_u32,
            stringify!(PcrSelectSize::$expected),
        );

        assert_eq!(
            PcrSelectSize::$expected,
            PcrSelectSize::try_parse_usize(expected_usize).expect(&format!(
                "try_parse_usize failed to parse value {}",
                expected_usize
            )),
            "The usize value {} did not get parsed as the expected {}",
            expected_u32,
            stringify!(PcrSelectSize::$expected),
        );

        assert_eq!(
            PcrSelectSize::$expected,
            PcrSelectSize::try_from(expected_u8).expect(&format!(
                "Failed to convert u8 value {} to a PcrSelectSize",
                expected_u8
            )),
            "The value {} did not get converted into the expected {}",
            expected_u8,
            stringify!(PcrSelectSize::$expected),
        );

        assert_eq!(
            expected_u8,
            u8::try_from(PcrSelectSize::$expected).expect(&format!(
                "Failed to convert {} to u8 value",
                stringify!(PcrSelectSize::$expected)
            )),
            "{} did not get converted into the expected u8 value {}",
            stringify!(PcrSelectSize::$expected),
            expected_u8,
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversions!(PcrSelectSize::OneByte, 1);
    test_valid_conversions!(PcrSelectSize::TwoBytes, 2);
    test_valid_conversions!(PcrSelectSize::ThreeBytes, 3);
    test_valid_conversions!(PcrSelectSize::FourBytes, 4);
}

#[test]
fn test_invalid_conversions() {
    for value in 5..=u8::MAX {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            PcrSelectSize::try_from(value),
            "Converting an invalid size_of_select value{} did not result in the expected error",
            value,
        );
    }
}

#[test]
fn test_default() {
    // The default valuen should be the value that
    // works on most platforms i.e. three octets.
    assert_eq!(
        PcrSelectSize::ThreeBytes,
        PcrSelectSize::default(),
        "PcrSelectSize did not have the expected default value",
    );
}
