// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    error::{Error, WrapperErrorKind},
    interface_types::algorithm::{HashingAlgorithm, RsaDecryptAlgorithm},
    structures::{HashScheme, RsaDecryptionScheme},
    tss2_esys::{TPMT_RSA_DECRYPT, TPMU_ASYM_SCHEME},
};

use std::convert::TryFrom;

macro_rules! assert_create_ok {
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_create_ok!(
            RsaDecryptAlgorithm::$scheme_alg_item,
            Some(HashingAlgorithm::$hash_alg)
        );
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident) => {
        assert_create_ok!(
            RsaDecryptAlgorithm::$scheme_alg_item,
            None::<HashingAlgorithm>
        );
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, $hash_alg_expr:expr) => {
        assert!(
            RsaDecryptionScheme::create(RsaDecryptAlgorithm::$scheme_alg_item, $hash_alg_expr)
                .is_ok()
        );
    };
}

#[test]
fn test_create_associated_function() {
    assert_create_ok!(RsaDecryptAlgorithm::RsaEs);
    assert_create_ok!(RsaDecryptAlgorithm::Oaep, HashingAlgorithm::Sha3_256);
    assert_create_ok!(RsaDecryptAlgorithm::Null);
}

macro_rules! assert_error {
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_error!(RsaDecryptAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, Some(HashingAlgorithm::$hash_alg));
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident) => {
        assert_error!(RsaDecryptAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, None::<HashingAlgorithm>);
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, $hash_alg_expr:expr) => {
        let scheme_alg = RsaDecryptAlgorithm::$scheme_alg_item;
        let hash_alg = $hash_alg_expr;
        if let Err(actual_error) = RsaDecryptionScheme::create(scheme_alg, hash_alg) {
            assert_eq!(
                Error::WrapperError(WrapperErrorKind::$error_kind),
                actual_error
            );
        } else {
            panic!(
                "Calling `create` function in `{}` with invalid input({:?}, {:?}) did not produce an error.",
                std::any::type_name::<RsaDecryptionScheme>(), scheme_alg, hash_alg,
            );
        }
    }
}

#[test]
fn test_create_associated_function_with_invalid_input() {
    assert_error!(
        RsaDecryptAlgorithm::RsaEs,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha3_384
    );
    assert_error!(RsaDecryptAlgorithm::Oaep, WrapperErrorKind::ParamsMissing);
    assert_error!(
        RsaDecryptAlgorithm::Null,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha3_384
    );
}

macro_rules! assert_algorithm {
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_algorithm!(
            RsaDecryptAlgorithm::$scheme_alg_item,
            RsaDecryptionScheme::$scheme_alg_item(HashScheme::new(HashingAlgorithm::$hash_alg))
        );
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident) => {
        assert_algorithm!(
            RsaDecryptAlgorithm::$scheme_alg_item,
            RsaDecryptionScheme::$scheme_alg_item
        );
    };
    (RsaDecryptAlgorithm::$scheme_alg_item:ident, $scheme_expr:expr) => {
        let actual = $scheme_expr.algorithm();
        let expected = RsaDecryptAlgorithm::$scheme_alg_item;
        assert_eq!(expected, actual);
    };
}

#[test]
fn test_algorithm_method() {
    assert_algorithm!(RsaDecryptAlgorithm::RsaEs);
    assert_algorithm!(RsaDecryptAlgorithm::Oaep, HashingAlgorithm::Sha3_256);
    assert_algorithm!(RsaDecryptAlgorithm::Null);
}

macro_rules! test_conversions {
    (RsaDecryptionScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $details:ident) => {
        test_conversions!(
            RsaDecryptionScheme::$scheme_item(HashScheme::new(HashingAlgorithm::$hash_item)),
            TPMT_RSA_DECRYPT  {
                scheme: RsaDecryptAlgorithm::$scheme_item.into(),
                details: TPMU_ASYM_SCHEME {
                    $details: HashScheme::new(HashingAlgorithm::$hash_item).into(),
                }
            }
        );
    };
    (RsaDecryptionScheme::$scheme_item:ident, $details:ident) => {
        test_conversions!(
            RsaDecryptionScheme::$scheme_item,
            TPMT_RSA_DECRYPT  {
                scheme: RsaDecryptAlgorithm::$scheme_item.into(),
                details: TPMU_ASYM_SCHEME {
                    $details: Default::default()
                }
            }
        );
    };
    (RsaDecryptionScheme::$scheme_item:ident) => {
        test_conversions!(RsaDecryptionScheme::$scheme_item, TPMT_RSA_DECRYPT {
            scheme: RsaDecryptAlgorithm::$scheme_item.into(),
            details: Default::default(),
        });
    };
    ($native:expr, $tss:expr) => {
        let expected_native = $native;
        let expected_tss = $tss;

        let actual_native = RsaDecryptionScheme::try_from(expected_tss)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a `TPMT_RSA_DECRYPT` with valid values into a `{}`.",
                    std::any::type_name::<RsaDecryptionScheme>(),
                );
            });
        assert_eq!(expected_native, actual_native);
        let actual_tss: TPMT_RSA_DECRYPT = expected_native.into();
        crate::common::ensure_tpmt_rsa_decrypt_equality(&expected_tss, &actual_tss);
    }
}

#[test]
fn test_valid_conversions() {
    test_conversions!(RsaDecryptionScheme::RsaEs, rsaes);
    test_conversions!(RsaDecryptionScheme::Oaep, HashingAlgorithm::Sha3_256, oaep);
    test_conversions!(RsaDecryptionScheme::Null);
}
