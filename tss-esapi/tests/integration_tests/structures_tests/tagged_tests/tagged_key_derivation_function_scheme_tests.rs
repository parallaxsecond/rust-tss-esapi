// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    interface_types::algorithm::{HashingAlgorithm, KeyDerivationFunction},
    structures::{HashScheme, KeyDerivationFunctionScheme},
    tss2_esys::{TPMT_KDF_SCHEME, TPMU_KDF_SCHEME},
};

macro_rules! test_conversions {
    (KeyDerivationFunctionScheme::$scheme_item:ident, HashingAlgorithm::$hash_item:ident, $details:ident) => {
        test_conversions!(
            KeyDerivationFunctionScheme::$scheme_item(HashScheme::new(HashingAlgorithm::$hash_item)),
            TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::$scheme_item.into(),
                details: TPMU_KDF_SCHEME {
                    $details: HashScheme::new(HashingAlgorithm::$hash_item).into(),
                }
            }
        );
    };
    (KeyDerivationFunctionScheme::$scheme_item:ident) => {
        test_conversions!(KeyDerivationFunctionScheme::$scheme_item, TPMT_KDF_SCHEME {
            scheme: KeyDerivationFunction::$scheme_item.into(),
            details: Default::default(),
        });
    };
    ($native:expr, $tss:expr) => {
        let expected_native = $native;
        let expected_tss = $tss;

        let actual_native = KeyDerivationFunctionScheme::try_from(expected_tss)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a `TPMT_KDF_SCHEME` with valid values into a `{}`.",
                    std::any::type_name::<KeyDerivationFunctionScheme>(),
                );
            });
        assert_eq!(expected_native, actual_native);
        let actual_tss: TPMT_KDF_SCHEME = expected_native.into();
        crate::common::ensure_tpmt_kdf_scheme_equality(&expected_tss, &actual_tss);
    }
}

#[test]
fn test_valid_conversions() {
    test_conversions!(
        KeyDerivationFunctionScheme::Kdf1Sp800_56a,
        HashingAlgorithm::Sha3_512,
        kdf1_sp800_56a
    );
    test_conversions!(
        KeyDerivationFunctionScheme::Kdf2,
        HashingAlgorithm::Sha3_512,
        kdf2
    );
    test_conversions!(
        KeyDerivationFunctionScheme::Kdf1Sp800_108,
        HashingAlgorithm::Sha3_512,
        kdf1_sp800_108
    );
    test_conversions!(
        KeyDerivationFunctionScheme::Mgf1,
        HashingAlgorithm::Sha3_512,
        mgf1
    );
    test_conversions!(KeyDerivationFunctionScheme::Null);
}
