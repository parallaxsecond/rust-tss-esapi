// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::AlgorithmIdentifier,
    error::{Error, WrapperErrorKind},
    interface_types::algorithm::{EccSchemeAlgorithm, HashingAlgorithm},
    structures::{EcDaaScheme, EccScheme, HashScheme},
    tss2_esys::{TPMT_ECC_SCHEME, TPMU_ASYM_SCHEME},
};

macro_rules! assert_create_ok {
    (EccSchemeAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident, $count_expr:expr) => {
        assert_create_ok!(
            EccSchemeAlgorithm::$scheme_alg_item,
            Some(HashingAlgorithm::$hash_alg),
            Some($count_expr)
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_create_ok!(
            EccSchemeAlgorithm::$scheme_alg_item,
            Some(HashingAlgorithm::$hash_alg),
            None::<u16>
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident) => {
        assert_create_ok!(
            EccSchemeAlgorithm::$scheme_alg_item,
            None::<HashingAlgorithm>,
            None::<u16>
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, $hash_alg_expr:expr, $count_expr:expr) => {
        assert!(EccScheme::create(
            EccSchemeAlgorithm::$scheme_alg_item,
            $hash_alg_expr,
            $count_expr
        )
        .is_ok());
    };
}

#[test]
fn test_create_associated_function() {
    assert_create_ok!(EccSchemeAlgorithm::EcDsa, HashingAlgorithm::Sha256);
    assert_create_ok!(EccSchemeAlgorithm::EcDh, HashingAlgorithm::Sha256);
    assert_create_ok!(EccSchemeAlgorithm::EcDaa, HashingAlgorithm::Sha256, 1u16);
    assert_create_ok!(EccSchemeAlgorithm::Sm2, HashingAlgorithm::Sha256);
    assert_create_ok!(EccSchemeAlgorithm::EcSchnorr, HashingAlgorithm::Sha256);
    assert_create_ok!(EccSchemeAlgorithm::EcMqv, HashingAlgorithm::Sha256);
    assert_create_ok!(EccSchemeAlgorithm::Null);
}

macro_rules! assert_error {
    (EccSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, HashingAlgorithm::$hash_alg:ident, $count_expr:expr) => {
        assert_error!(EccSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, Some(HashingAlgorithm::$hash_alg), Some($count_expr));
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_error!(EccSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, Some(HashingAlgorithm::$hash_alg), None::<u16>);
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, $count_expr:expr) => {
        assert_error!(EccSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, None::<HashingAlgorithm>, Some($count_expr));
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident) => {
        assert_error!(EccSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, None::<HashingAlgorithm>, None::<u16>);
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, $hash_alg_expr:expr, $count_expr:expr) => {
        let scheme_alg = EccSchemeAlgorithm::$scheme_alg_item;
        let hash_alg = $hash_alg_expr;
        let count = $count_expr;
        if let Err(actual_error) = EccScheme::create(scheme_alg, hash_alg, count) {
            assert_eq!(
                Error::WrapperError(WrapperErrorKind::$error_kind),
                actual_error
            );
        } else {
            panic!(
                "Calling `create` function in `{}` with invalid input({:?}, {:?}, {:?}) did not produce an error.",
                std::any::type_name::<EccScheme>(), scheme_alg, hash_alg, count,
            );
        }
    }
}

#[test]
fn test_create_associated_function_with_invalid_input() {
    assert_error!(EccSchemeAlgorithm::EcDsa, WrapperErrorKind::ParamsMissing);
    assert_error!(
        EccSchemeAlgorithm::EcDsa,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );
    assert_error!(EccSchemeAlgorithm::EcDh, WrapperErrorKind::ParamsMissing);
    assert_error!(
        EccSchemeAlgorithm::EcDh,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );
    assert_error!(EccSchemeAlgorithm::EcDaa, WrapperErrorKind::ParamsMissing);
    assert_error!(
        EccSchemeAlgorithm::EcDaa,
        WrapperErrorKind::ParamsMissing,
        HashingAlgorithm::Sha256
    );
    assert_error!(
        EccSchemeAlgorithm::EcDaa,
        WrapperErrorKind::ParamsMissing,
        1u16
    );
    assert_error!(EccSchemeAlgorithm::Sm2, WrapperErrorKind::ParamsMissing);
    assert_error!(
        EccSchemeAlgorithm::Sm2,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );
    assert_error!(
        EccSchemeAlgorithm::EcSchnorr,
        WrapperErrorKind::ParamsMissing
    );
    assert_error!(
        EccSchemeAlgorithm::EcSchnorr,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );
    assert_error!(EccSchemeAlgorithm::EcMqv, WrapperErrorKind::ParamsMissing);
    assert_error!(
        EccSchemeAlgorithm::EcMqv,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );

    assert_error!(
        EccSchemeAlgorithm::Null,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256
    );
    assert_error!(
        EccSchemeAlgorithm::Null,
        WrapperErrorKind::InconsistentParams,
        1u16
    );
    assert_error!(
        EccSchemeAlgorithm::Null,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256,
        1u16
    );
}

macro_rules! assert_algorithm {
    (EccSchemeAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident, $count_expr:expr) => {
        assert_algorithm!(
            EccSchemeAlgorithm::$scheme_alg_item,
            EccScheme::$scheme_alg_item(EcDaaScheme::new(HashingAlgorithm::$hash_alg, $count_expr))
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_algorithm!(
            EccSchemeAlgorithm::$scheme_alg_item,
            EccScheme::$scheme_alg_item(HashScheme::new(HashingAlgorithm::$hash_alg))
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident) => {
        assert_algorithm!(
            EccSchemeAlgorithm::$scheme_alg_item,
            EccScheme::$scheme_alg_item
        );
    };
    (EccSchemeAlgorithm::$scheme_alg_item:ident, $scheme_expr:expr) => {
        let actual = $scheme_expr.algorithm();
        let expected = EccSchemeAlgorithm::$scheme_alg_item;
        assert_eq!(expected, actual);
    };
}

#[test]
fn test_algorithm_method() {
    assert_algorithm!(EccSchemeAlgorithm::EcDsa, HashingAlgorithm::Sha256);
    assert_algorithm!(EccSchemeAlgorithm::EcDh, HashingAlgorithm::Sha256);
    assert_algorithm!(EccSchemeAlgorithm::EcDaa, HashingAlgorithm::Sha256, 1u16);
    assert_algorithm!(EccSchemeAlgorithm::Sm2, HashingAlgorithm::Sha256);
    assert_algorithm!(EccSchemeAlgorithm::EcSchnorr, HashingAlgorithm::Sha256);
    assert_algorithm!(EccSchemeAlgorithm::EcMqv, HashingAlgorithm::Sha256);
    assert_algorithm!(EccSchemeAlgorithm::Null);
}

macro_rules! test_conversions {
    (EccScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $count_expr:expr, $details:ident) => {
        test_conversions!(
            EccScheme::$scheme_item(EcDaaScheme::new(HashingAlgorithm::$hash_item, $count_expr)),
            TPMT_ECC_SCHEME {
                scheme: EccSchemeAlgorithm::$scheme_item.into(),
                details: TPMU_ASYM_SCHEME {
                    $details: EcDaaScheme::new(HashingAlgorithm::$hash_item, $count_expr).into(),
                }
            }
        );
    };
    (EccScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $details:ident) => {
        test_conversions!(
            EccScheme::$scheme_item(HashScheme::new(HashingAlgorithm::$hash_item)),
            TPMT_ECC_SCHEME {
                scheme: EccSchemeAlgorithm::$scheme_item.into(),
                details: TPMU_ASYM_SCHEME {
                    $details: HashScheme::new(HashingAlgorithm::$hash_item).into(),
                }
            }
        );
    };
    (EccScheme::$scheme_item:ident) => {
        test_conversions!(EccScheme::$scheme_item, TPMT_ECC_SCHEME {
            scheme: EccSchemeAlgorithm::$scheme_item.into(),
            details: Default::default(),
        });
    };
    ($native:expr, $tss:expr) => {
        let expected_native = $native;
        let expected_tss = $tss;

        let actual_native = EccScheme::try_from(expected_tss)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a `TPMT_ECC_SCHEME` with valid values into a `{}`.",
                    std::any::type_name::<EccScheme>(),
                );
            });
        assert_eq!(expected_native, actual_native);
        let actual_tss: TPMT_ECC_SCHEME = expected_native.into();
        crate::common::ensure_tpmt_ecc_scheme_equality(&expected_tss, &actual_tss);
    }
}

#[test]
fn test_valid_conversions() {
    test_conversions!(EccScheme::EcDsa, HashingAlgorithm::Sha256, ecdsa);
    test_conversions!(EccScheme::EcDh, HashingAlgorithm::Sha256, ecdh);
    test_conversions!(EccScheme::EcDaa, HashingAlgorithm::Sha256, 1u16, ecdaa);
    test_conversions!(EccScheme::Sm2, HashingAlgorithm::Sha256, sm2);
    test_conversions!(EccScheme::EcSchnorr, HashingAlgorithm::Sha256, ecschnorr);
    test_conversions!(EccScheme::EcMqv, HashingAlgorithm::Sha256, ecmqv);
    test_conversions!(EccScheme::Null);
}

#[test]
fn test_invalid_conversion() {
    let invalid_tss = TPMT_ECC_SCHEME {
        scheme: AlgorithmIdentifier::Aes.into(),
        details: Default::default(),
    };

    assert!(EccScheme::try_from(invalid_tss).is_err());
}
