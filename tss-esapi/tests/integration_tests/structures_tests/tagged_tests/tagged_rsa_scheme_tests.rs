// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    constants::AlgorithmIdentifier,
    error::{Error, WrapperErrorKind},
    interface_types::algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
    structures::{HashScheme, RsaScheme},
    tss2_esys::{TPMT_RSA_SCHEME, TPMU_ASYM_SCHEME},
};

use std::convert::TryFrom;

#[test]
fn test_create_associated_function() {
    assert!(RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256)).is_ok());
    assert!(RsaScheme::create(RsaSchemeAlgorithm::RsaEs, None).is_ok());
    assert!(RsaScheme::create(RsaSchemeAlgorithm::RsaPss, Some(HashingAlgorithm::Sha1)).is_ok());
    assert!(RsaScheme::create(RsaSchemeAlgorithm::Oaep, Some(HashingAlgorithm::Sha3_384)).is_ok());
    assert!(RsaScheme::create(RsaSchemeAlgorithm::Null, None).is_ok());
}

macro_rules! assert_error {
    (RsaSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, HashingAlgorithm::$hash_alg:ident) => {
        assert_error!(RsaSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, Some(HashingAlgorithm::$hash_alg));
    };
    (RsaSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident) => {
        assert_error!(RsaSchemeAlgorithm::$scheme_alg_item, WrapperErrorKind::$error_kind, None::<HashingAlgorithm>);
    };
    (RsaSchemeAlgorithm::$scheme_alg_item:ident, WrapperErrorKind::$error_kind:ident, $hash_alg_expr:expr) => {
        let scheme_alg = RsaSchemeAlgorithm::$scheme_alg_item;
        let hash_alg = $hash_alg_expr;
        if let Err(actual_error) = RsaScheme::create(scheme_alg, hash_alg) {
            assert_eq!(
                Error::WrapperError(WrapperErrorKind::$error_kind),
                actual_error
            );
        } else {
            panic!(
                "Calling `create` function in `{}` with invalid input({:?}, {:?}) did not produce an error.",
                std::any::type_name::<RsaScheme>(), scheme_alg, hash_alg,
            );
        }
    }
}

#[test]
fn test_create_associated_function_with_invalid_input() {
    assert_error!(RsaSchemeAlgorithm::RsaSsa, WrapperErrorKind::ParamsMissing);
    assert_error!(
        RsaSchemeAlgorithm::RsaEs,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha256
    );
    assert_error!(RsaSchemeAlgorithm::RsaPss, WrapperErrorKind::ParamsMissing);
    assert_error!(RsaSchemeAlgorithm::Oaep, WrapperErrorKind::ParamsMissing);
    assert_error!(
        RsaSchemeAlgorithm::Null,
        WrapperErrorKind::InconsistentParams,
        HashingAlgorithm::Sha3_256
    );
}

macro_rules! assert_algorithm {
    (RsaScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident) => {
        let scheme = RsaScheme::$scheme_item(HashScheme::new(HashingAlgorithm::$hash_item));
        assert_eq!(RsaSchemeAlgorithm::$scheme_item, scheme.algorithm());
    };
    (RsaScheme::$scheme_item:ident) => {
        let scheme = RsaScheme::$scheme_item;
        assert_eq!(RsaSchemeAlgorithm::$scheme_item, scheme.algorithm());
    };
}

#[test]
fn test_algorithm_method() {
    assert_algorithm!(RsaScheme::RsaSsa, HashingAlgorithm::Sha256);
    assert_algorithm!(RsaScheme::RsaEs);
    assert_algorithm!(RsaScheme::RsaPss, HashingAlgorithm::Sha1);
    assert_algorithm!(RsaScheme::Oaep, HashingAlgorithm::Sha3_512);
    assert_algorithm!(RsaScheme::Null);
}

macro_rules! test_conversions {
    (RsaScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $details:ident) => {
        test_conversions!(RsaScheme::$scheme_item(HashScheme::new(HashingAlgorithm::$hash_item)), TPMT_RSA_SCHEME {
            scheme: RsaSchemeAlgorithm::$scheme_item.into(),
            details: TPMU_ASYM_SCHEME {
                $details: HashScheme::new(HashingAlgorithm::$hash_item).into(),
            },
        });
    };

    (RsaScheme::$scheme_item:ident, $details:ident) => {
        test_conversions!(RsaScheme::$scheme_item, TPMT_RSA_SCHEME {
            scheme: RsaSchemeAlgorithm::$scheme_item.into(),
            details: TPMU_ASYM_SCHEME {
                $details: Default::default(),
            },
        });
    };

    (RsaScheme::$scheme_item:ident) => {
        test_conversions!(RsaScheme::$scheme_item, TPMT_RSA_SCHEME {
            scheme: RsaSchemeAlgorithm::$scheme_item.into(),
            details: Default::default(),
        });
    };

    ($native:expr, $tss:expr) => {
        let expected_native = $native;
        let expected_tss = $tss;

        let actual_native = RsaScheme::try_from(expected_tss)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a `TPMT_RSA_SCHEME` with valid values into a `{}`.",
                    std::any::type_name::<RsaScheme>(),
                );
            });
        assert_eq!(expected_native, actual_native);
        let actual_tss: TPMT_RSA_SCHEME = expected_native.into();
        crate::common::ensure_tpmt_rsa_scheme_equality(&expected_tss, &actual_tss);
    }
}

#[test]
fn test_valid_conversions() {
    test_conversions!(RsaScheme::RsaSsa, HashingAlgorithm::Sha256, rsassa);
    test_conversions!(RsaScheme::RsaEs, rsaes);
    test_conversions!(RsaScheme::RsaPss, HashingAlgorithm::Sha512, rsapss);
    test_conversions!(RsaScheme::Oaep, HashingAlgorithm::Sm3_256, oaep);
    test_conversions!(RsaScheme::Null);
}

#[test]
fn test_invalid_conversion() {
    let invalid_tss = TPMT_RSA_SCHEME {
        scheme: AlgorithmIdentifier::Aes.into(),
        details: Default::default(),
    };

    assert!(RsaScheme::try_from(invalid_tss).is_err());
}
