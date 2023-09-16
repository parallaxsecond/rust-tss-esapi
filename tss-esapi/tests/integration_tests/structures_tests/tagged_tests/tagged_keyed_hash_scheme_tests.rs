// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::common::ensure_tpmt_keyedhash_scheme_equality;
use std::convert::TryFrom;
use tss_esapi::{
    constants::AlgorithmIdentifier,
    error::{Error, WrapperErrorKind},
    interface_types::algorithm::{
        HashingAlgorithm, KeyDerivationFunction, KeyedHashSchemeAlgorithm,
    },
    structures::{HmacScheme, KeyedHashScheme, XorScheme},
    tss2_esys::{TPMT_KEYEDHASH_SCHEME, TPMU_SCHEME_KEYEDHASH},
};

#[test]
fn test_keyed_hash_xor_scheme_conversions() {
    let algorithm = KeyedHashSchemeAlgorithm::Xor;
    let scheme_hashing_algorithm = HashingAlgorithm::Sha384;
    let scheme_key_derivation_function = KeyDerivationFunction::Kdf2;
    let scheme = XorScheme::new(scheme_hashing_algorithm, scheme_key_derivation_function);

    let expected_native = KeyedHashScheme::Xor { xor_scheme: scheme };

    let expected_tss = TPMT_KEYEDHASH_SCHEME {
        scheme: algorithm.into(),
        details: TPMU_SCHEME_KEYEDHASH {
            exclusiveOr: scheme.into(),
        },
    };

    let actual_native = KeyedHashScheme::try_from(expected_tss).expect(
        "It should be possible to convert a valid `TPMT_KEYEDHASH_SCHEME` into a `KeyedHashScheme`.",
    );

    let actual_tss: TPMT_KEYEDHASH_SCHEME = expected_native.into();

    assert_eq!(expected_native, actual_native);
    ensure_tpmt_keyedhash_scheme_equality(&expected_tss, &actual_tss);
}

#[test]
fn test_keyed_hash_hmac_scheme_conversions() {
    let algorithm = KeyedHashSchemeAlgorithm::Hmac;
    let scheme_hashing_algorithm = HashingAlgorithm::Sha384;
    let scheme = HmacScheme::new(scheme_hashing_algorithm);

    let expected_native = KeyedHashScheme::Hmac {
        hmac_scheme: scheme,
    };

    let expected_tss = TPMT_KEYEDHASH_SCHEME {
        scheme: algorithm.into(),
        details: TPMU_SCHEME_KEYEDHASH {
            hmac: scheme.into(),
        },
    };

    let actual_native = KeyedHashScheme::try_from(expected_tss).expect(
        "It should be possible to convert a valid `TPMT_KEYEDHASH_SCHEME` into a `KeyedHashScheme`.",
    );

    let actual_tss: TPMT_KEYEDHASH_SCHEME = expected_native.into();

    assert_eq!(expected_native, actual_native);
    ensure_tpmt_keyedhash_scheme_equality(&expected_tss, &actual_tss);
}

#[test]
fn test_keyed_hash_null_scheme_conversions() {
    let algorithm = KeyedHashSchemeAlgorithm::Null;

    let expected_native = KeyedHashScheme::Null;

    let expected_tss = TPMT_KEYEDHASH_SCHEME {
        scheme: algorithm.into(),
        details: Default::default(),
    };

    let actual_native = KeyedHashScheme::try_from(expected_tss).expect(
        "It should be possible to convert a valid `TPMT_KEYEDHASH_SCHEME` into a `KeyedHashScheme`.",
    );

    let actual_tss: TPMT_KEYEDHASH_SCHEME = expected_native.into();

    assert_eq!(expected_native, actual_native);
    ensure_tpmt_keyedhash_scheme_equality(&expected_tss, &actual_tss);
}

#[test]
fn test_keyed_hash_scheme_invalid_conversion() {
    let invalid_algorithm = AlgorithmIdentifier::Rsa;
    let scheme_hashing_algorithm = HashingAlgorithm::Sha384;
    let scheme = HmacScheme::new(scheme_hashing_algorithm);

    let invalid_tss = TPMT_KEYEDHASH_SCHEME {
        scheme: invalid_algorithm.into(),
        details: TPMU_SCHEME_KEYEDHASH {
            hmac: scheme.into(),
        },
    };

    let expected_error = Error::WrapperError(WrapperErrorKind::InvalidParam);

    if let Err(actual_error) = KeyedHashScheme::try_from(invalid_tss) {
        assert_eq!(expected_error, actual_error);
    } else {
        panic!("`TPMT_KEYEDHASH_SCHEME` with invalid values did not result in an error when converted to `KeyedHashScheme`.");
    };
}
