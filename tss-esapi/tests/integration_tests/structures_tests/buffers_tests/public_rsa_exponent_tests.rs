// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{structures::RsaExponent, Error, WrapperErrorKind};
#[test]
fn rsa_exponent_create_test() {
    let expected_error = Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    // Valid values for RsaExponent are only 0 or a prime number value larger then 2.
    assert_eq!(expected_error, RsaExponent::create(1));

    // The specification says that 0 or any prime number larger then 2 should be accepted.
    let _ = RsaExponent::create(0).expect("Failed to create a RsaExponent from the value 0");
    let _ = RsaExponent::create(5).expect("Failed to create a RsaExponent from the value 5");
}

#[test]
fn rsa_exponent_is_valid_test() {
    assert!(!RsaExponent::is_valid(1));
    assert!(RsaExponent::is_valid(17));
}

#[test]
fn rsa_exponent_value_test() {
    let expected_value = 97;

    let rsa_exponent = RsaExponent::create(expected_value).unwrap_or_else(|_| {
        panic!(
            "Failed to create a RsaExponent from the value {}",
            expected_value
        )
    });

    assert_eq!(expected_value, rsa_exponent.value());
}
