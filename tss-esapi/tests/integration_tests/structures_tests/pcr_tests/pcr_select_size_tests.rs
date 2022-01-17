// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{structures::PcrSelectSize, Error, WrapperErrorKind};

macro_rules! test_valid_conversions {
    (PcrSelectSize::$expected:ident, $value:expr) => {
        let expected_u8: u8 = $value;
        let expected_usize: usize = $value;

        let actual = PcrSelectSize::try_from(expected_u8).expect(&format!(
            "Failed to convert {} to PcrSelectSize",
            expected_u8
        ));

        assert_eq!(
            PcrSelectSize::$expected,
            actual,
            "PcrSelectSize converted from {} did not match the expected value {}",
            expected_u8,
            stringify!(PcrSelectSize::$expected),
        );

        assert_eq!(
            expected_u8,
            u8::from(actual),
            "PcrSelectSize {} did not convert to the expected u8 value {}",
            stringify!(PcrSelectSize::$expected),
            expected_u8
        );

        assert_eq!(
            expected_usize,
            usize::from(actual),
            "PcrSelectSize {} did not convert to the expected usize value {}",
            stringify!(PcrSelectSize::$expected),
            expected_usize
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
