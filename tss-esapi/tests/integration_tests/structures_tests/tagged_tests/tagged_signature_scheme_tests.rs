// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    interface_types::algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
    structures::{EcDaaScheme, HashScheme, HmacScheme, SignatureScheme},
    tss2_esys::{TPMT_SIG_SCHEME, TPMU_SIG_SCHEME},
    Error, WrapperErrorKind,
};

use std::convert::TryFrom;

macro_rules! assert_signing_scheme {
    (SignatureScheme::$scheme_item:ident, $scheme_type:ty, HashingAlgorithm::$hash_item:ident, $count_expr:expr) => {
        assert_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: <$scheme_type>::new(HashingAlgorithm::$hash_item, $count_expr)},
            HashingAlgorithm::$hash_item
        );
    };
    (SignatureScheme::$scheme_item:ident, $scheme_type:ty, HashingAlgorithm::$hash_item:ident) => {
        assert_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: <$scheme_type>::new(HashingAlgorithm::$hash_item)},
            HashingAlgorithm::$hash_item
        );
    };
    (SignatureScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident) => {
        assert_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: HashScheme::new(HashingAlgorithm::$hash_item)},
            HashingAlgorithm::$hash_item
        );
    };
    ($item_expr:expr, HashingAlgorithm::$hash_item:ident) => {
        let item = $item_expr;
        let actual = item.signing_scheme().unwrap_or_else(|_| {
            panic!(
                "A valid {} that contains a scheme should not return an error when calling the `signing_scheme` method.",
                std::any::type_name::<SignatureScheme>()
            );
        });
        let expected = HashingAlgorithm::$hash_item;
        assert_eq!(expected, actual);
    }
}

#[test]
fn test_signing_scheme_method() {
    assert_signing_scheme!(SignatureScheme::RsaSsa, HashingAlgorithm::Sha1);
    assert_signing_scheme!(SignatureScheme::RsaPss, HashingAlgorithm::Sha256);
    assert_signing_scheme!(SignatureScheme::EcDsa, HashingAlgorithm::Sha512);
    assert_signing_scheme!(SignatureScheme::Sm2, HashingAlgorithm::Sha3_256);
    assert_signing_scheme!(SignatureScheme::EcSchnorr, HashingAlgorithm::Sha3_384);
    assert_signing_scheme!(
        SignatureScheme::EcDaa,
        EcDaaScheme,
        HashingAlgorithm::Sha3_512,
        1u16
    );
    assert_signing_scheme!(SignatureScheme::Hmac, HmacScheme, HashingAlgorithm::Sha1);
}

macro_rules! assert_signing_scheme_error {
    (SignatureScheme::$scheme_item:ident, WrapperErrorKind::$error_kind:ident) => {
        if let Err(actual) = SignatureScheme::$scheme_item.signing_scheme() {
            let expected = Error::WrapperError(WrapperErrorKind::$error_kind);
            assert_eq!(expected, actual);
        } else {
            panic!(
                "Calling `signing_scheme` method on {} object did not produce an error.",
                std::stringify!(SignatureScheme::$scheme_item)
            );
        }
    };
}

#[test]
fn test_signing_scheme_method_with_invalid_input() {
    assert_signing_scheme_error!(SignatureScheme::Null, WrapperErrorKind::InvalidParam);
}

macro_rules! assert_set_signing_scheme {
    (SignatureScheme::$scheme_item:ident, $scheme_type:ty, HashingAlgorithm::$hash_item:ident, $count_expr:expr) => {
        assert_set_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: <$scheme_type>::new(HashingAlgorithm::Sha256, $count_expr)},
            HashingAlgorithm::$hash_item
        );
    };
    (SignatureScheme::$scheme_item:ident, $scheme_type:ty, HashingAlgorithm::$hash_item:ident) => {
        assert_set_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: <$scheme_type>::new(HashingAlgorithm::Sha256)},
            HashingAlgorithm::$hash_item
        );
    };
    (SignatureScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident) => {
        assert_set_signing_scheme!(
            SignatureScheme::$scheme_item{scheme: HashScheme::new(HashingAlgorithm::Sha256)},
            HashingAlgorithm::$hash_item
        );
    };
    ($item_expr:expr, HashingAlgorithm::$hash_item:ident) => {
        let mut item = $item_expr;
        item.set_signing_scheme(HashingAlgorithm::$hash_item).unwrap_or_else(|_| {
            panic!(
                "Should be possible to call `set_signing_scheme` method on any {} that is not the Null scheme.",
                std::any::type_name::<SignatureScheme>()
            );
        });
        let actual = item.signing_scheme().unwrap_or_else(|_| {
            panic!(
                "A valid {} that contains a scheme should not return an error when calling the `signing_scheme` method.",
                std::any::type_name::<SignatureScheme>()
            );
        });
        let expected = HashingAlgorithm::$hash_item;
        assert_eq!(
            expected,
            actual,
            "Signing scheme mismatch after using `set_signing_scheme` method for {}.",
            std::stringify!($item_expr)
        );
    }
}

#[test]
fn test_set_signing_scheme_method() {
    assert_set_signing_scheme!(SignatureScheme::RsaSsa, HashingAlgorithm::Sha1);
    assert_set_signing_scheme!(SignatureScheme::RsaPss, HashingAlgorithm::Sha256);
    assert_set_signing_scheme!(SignatureScheme::EcDsa, HashingAlgorithm::Sha512);
    assert_set_signing_scheme!(SignatureScheme::Sm2, HashingAlgorithm::Sha3_256);
    assert_set_signing_scheme!(SignatureScheme::EcSchnorr, HashingAlgorithm::Sha3_384);
    assert_set_signing_scheme!(
        SignatureScheme::EcDaa,
        EcDaaScheme,
        HashingAlgorithm::Sha3_512,
        1u16
    );
    assert_set_signing_scheme!(SignatureScheme::Hmac, HmacScheme, HashingAlgorithm::Sha1);
}

macro_rules! assert_set_signing_scheme_error {
    (SignatureScheme::$scheme_item:ident, WrapperErrorKind::$error_kind:ident) => {
        if let Err(actual) =
            SignatureScheme::$scheme_item.set_signing_scheme(HashingAlgorithm::Sha256)
        {
            let expected = Error::WrapperError(WrapperErrorKind::$error_kind);
            assert_eq!(expected, actual);
        } else {
            panic!(
                "Calling `signing_scheme` method on {} object did not produce an error.",
                std::stringify!(SignatureScheme::$scheme_item)
            );
        }
    };
}

#[test]
fn test_set_signing_scheme_method_with_invalid_input() {
    assert_set_signing_scheme_error!(SignatureScheme::Null, WrapperErrorKind::InvalidParam);
}

macro_rules! test_conversions {
    (SignatureScheme::$scheme_item:ident, $scheme_type:ty, HashingAlgorithm::$hash_item:ident, $count_expr:expr, $details:ident) => {
        test_conversions!(
            SignatureScheme::$scheme_item{scheme: <$scheme_type>::new(HashingAlgorithm::$hash_item, $count_expr)},
            TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::$scheme_item.into(),
                details: TPMU_SIG_SCHEME {
                    $details: <$scheme_type>::new(HashingAlgorithm::$hash_item, $count_expr).into()
                }
            }
        );
    };
    (SignatureScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $details:ident) => {
        test_conversions!(
            SignatureScheme::$scheme_item{ scheme: HashScheme::new(HashingAlgorithm::$hash_item) },
            TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::$scheme_item.into(),
                details: TPMU_SIG_SCHEME {
                    $details: HashScheme::new(HashingAlgorithm::$hash_item).into()
                }
            }
        );
    };
    ($native:expr, $tss:expr) => {
        let expected_native = $native;
        let expected_tss = $tss;

        let actual_native = SignatureScheme::try_from(expected_tss)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a `TPMT_SIG_SCHEME` with valid values into a `{}`.",
                    std::any::type_name::<SignatureScheme>(),
                );
            });
        assert_eq!(expected_native, actual_native);
        let actual_tss: TPMT_SIG_SCHEME = expected_native.into();
        crate::common::ensure_tpmt_sig_scheme_equality(&expected_tss, &actual_tss);
    }
}

#[test]
fn test_valid_conversions() {
    test_conversions!(SignatureScheme::RsaSsa, HashingAlgorithm::Sha1, rsassa);
    test_conversions!(SignatureScheme::RsaPss, HashingAlgorithm::Sha256, rsapss);
    test_conversions!(SignatureScheme::EcDsa, HashingAlgorithm::Sha512, ecdsa);
    test_conversions!(SignatureScheme::Sm2, HashingAlgorithm::Sha3_256, sm2);
    test_conversions!(
        SignatureScheme::EcSchnorr,
        HashingAlgorithm::Sha3_384,
        ecschnorr
    );
    test_conversions!(
        SignatureScheme::EcDaa,
        EcDaaScheme,
        HashingAlgorithm::Sha3_512,
        1u16,
        ecdaa
    );
}
