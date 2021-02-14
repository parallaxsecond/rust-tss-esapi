// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;

macro_rules! test_conversion {
    ($tpm_alg_id:ident, $interface_type:ident::$interface_type_item:ident) => {
        assert_eq!(
            Algorithm::$interface_type_item,
            $interface_type::$interface_type_item.into()
        );
        assert_eq!(
            $interface_type::try_from(Algorithm::$interface_type_item).expect(&format!(
                "Failed to parse from Algorithm for {}",
                stringify!($interface_type_item)
            )),
            $interface_type::$interface_type_item
        );
        assert_eq!(
            $tpm_alg_id,
            Algorithm::from($interface_type::$interface_type_item).into()
        );
        assert_eq!($tpm_alg_id, $interface_type::$interface_type_item.into());
        assert_eq!(
            $interface_type::$interface_type_item,
            $interface_type::try_from($tpm_alg_id).expect(&format!(
                "Failed to parse from alg if for {}",
                stringify!($tpm_alg_id)
            ))
        );
    };
}

mod test_hashing_algorithm_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{
                TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256,
                TPM2_ALG_SHA3_384, TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM3_256,
            },
            Algorithm,
        },
        interface_types::algorithm::HashingAlgorithm,
    };
    #[test]
    fn test_hashing_algorithm_conversion() {
        test_conversion!(TPM2_ALG_SHA1, HashingAlgorithm::Sha1);
        test_conversion!(TPM2_ALG_SHA256, HashingAlgorithm::Sha256);
        test_conversion!(TPM2_ALG_SHA384, HashingAlgorithm::Sha384);
        test_conversion!(TPM2_ALG_SHA512, HashingAlgorithm::Sha512);
        test_conversion!(TPM2_ALG_SM3_256, HashingAlgorithm::Sm3_256);
        test_conversion!(TPM2_ALG_SHA3_256, HashingAlgorithm::Sha3_256);
        test_conversion!(TPM2_ALG_SHA3_384, HashingAlgorithm::Sha3_384);
        test_conversion!(TPM2_ALG_SHA3_512, HashingAlgorithm::Sha3_512);
    }
}

mod test_keyed_hash_scheme_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{TPM2_ALG_HMAC, TPM2_ALG_NULL, TPM2_ALG_XOR},
            Algorithm,
        },
        interface_types::algorithm::KeyedHashSchemeAlgorithm,
    };
    #[test]
    fn test_keyed_hash_scheme_conversion() {
        test_conversion!(TPM2_ALG_HMAC, KeyedHashSchemeAlgorithm::Hmac);
        test_conversion!(TPM2_ALG_XOR, KeyedHashSchemeAlgorithm::Xor);
        test_conversion!(TPM2_ALG_NULL, KeyedHashSchemeAlgorithm::Null);
    }
}

mod test_key_derivation_function_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{
                TPM2_ALG_ECMQV, TPM2_ALG_KDF1_SP800_108, TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2,
            },
            Algorithm,
        },
        interface_types::algorithm::KeyDerivationFunction,
    };
    #[test]
    fn test_key_derivation_function_conversion() {
        test_conversion!(
            TPM2_ALG_KDF1_SP800_56A,
            KeyDerivationFunction::Kdf1Sp800_56a
        );
        test_conversion!(
            TPM2_ALG_KDF1_SP800_108,
            KeyDerivationFunction::Kdf1Sp800_108
        );
        test_conversion!(TPM2_ALG_KDF2, KeyDerivationFunction::Kdf2);
        test_conversion!(TPM2_ALG_ECMQV, KeyDerivationFunction::EcMqv);
    }
}

mod test_symmetric_algorithm_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{
                TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_NULL, TPM2_ALG_SM4, TPM2_ALG_TDES,
                TPM2_ALG_XOR,
            },
            Algorithm,
        },
        interface_types::algorithm::SymmetricAlgorithm,
    };
    #[test]
    fn test_symmetric_algorithm_conversion() {
        test_conversion!(TPM2_ALG_TDES, SymmetricAlgorithm::Tdes);
        test_conversion!(TPM2_ALG_AES, SymmetricAlgorithm::Aes);
        test_conversion!(TPM2_ALG_SM4, SymmetricAlgorithm::Sm4);
        test_conversion!(TPM2_ALG_CAMELLIA, SymmetricAlgorithm::Camellia);
        test_conversion!(TPM2_ALG_XOR, SymmetricAlgorithm::Xor);
        test_conversion!(TPM2_ALG_NULL, SymmetricAlgorithm::Null);
    }
}

mod test_symmetric_mode_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{TPM2_ALG_CFB, TPM2_ALG_CTR, TPM2_ALG_ECB, TPM2_ALG_NULL, TPM2_ALG_OFB},
            Algorithm,
        },
        interface_types::algorithm::SymmetricMode,
    };
    #[test]
    fn test_symmetric_mode_conversion() {
        test_conversion!(TPM2_ALG_CTR, SymmetricMode::Ctr);
        test_conversion!(TPM2_ALG_OFB, SymmetricMode::Ofb);
        test_conversion!(TPM2_ALG_CFB, SymmetricMode::Cfb);
        test_conversion!(TPM2_ALG_ECB, SymmetricMode::Ecb);
        test_conversion!(TPM2_ALG_NULL, SymmetricMode::Null);
    }
}

mod test_asymmetric_algorithm_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{TPM2_ALG_ECC, TPM2_ALG_NULL, TPM2_ALG_RSA},
            Algorithm,
        },
        interface_types::algorithm::AsymmetricAlgorithm,
    };

    #[test]
    fn test_asymmetric_algorithm_conversion() {
        test_conversion!(TPM2_ALG_RSA, AsymmetricAlgorithm::Rsa);
        test_conversion!(TPM2_ALG_ECC, AsymmetricAlgorithm::Ecc);
        test_conversion!(TPM2_ALG_NULL, AsymmetricAlgorithm::Null);
    }
}

mod test_signature_scheme_interface_type {
    use super::*;
    use std::convert::TryInto;
    use tss_esapi::{
        constants::{
            tss::{
                TPM2_ALG_ECDAA, TPM2_ALG_ECDSA, TPM2_ALG_ECSCHNORR, TPM2_ALG_HMAC, TPM2_ALG_NULL,
                TPM2_ALG_RSAPSS, TPM2_ALG_RSASSA, TPM2_ALG_SM2,
            },
            Algorithm,
        },
        interface_types::algorithm::{AsymmetricAlgorithm, SignatureScheme},
    };
    #[test]
    fn test_signature_scheme_conversion() {
        test_conversion!(TPM2_ALG_RSASSA, SignatureScheme::RsaSsa);
        test_conversion!(TPM2_ALG_RSAPSS, SignatureScheme::RsaPss);
        test_conversion!(TPM2_ALG_ECDSA, SignatureScheme::EcDsa);
        test_conversion!(TPM2_ALG_ECDAA, SignatureScheme::EcDaa);
        test_conversion!(TPM2_ALG_SM2, SignatureScheme::Sm2);
        test_conversion!(TPM2_ALG_ECSCHNORR, SignatureScheme::EcSchnorr);
        test_conversion!(TPM2_ALG_HMAC, SignatureScheme::Hmac);
        test_conversion!(TPM2_ALG_NULL, SignatureScheme::Null);
    }

    #[test]
    fn test_special_conversion_into_asymmetric_algorithm() {
        assert_eq!(
            AsymmetricAlgorithm::Rsa,
            SignatureScheme::RsaSsa
                .try_into()
                .expect("Failed to convert RsaSsa into asymmetric algorithm")
        );
        assert_eq!(
            AsymmetricAlgorithm::Rsa,
            SignatureScheme::RsaPss
                .try_into()
                .expect("Failed to convert RsaPss into asymmetric algorithm")
        );
        assert_eq!(
            AsymmetricAlgorithm::Ecc,
            SignatureScheme::EcDsa
                .try_into()
                .expect("Failed to convert EcDsa into asymmetric algorithm")
        );
        assert_eq!(
            AsymmetricAlgorithm::Ecc,
            SignatureScheme::EcDaa
                .try_into()
                .expect("Failed to convert EcDaa into asymmetric algorithm")
        );
        assert_eq!(
            AsymmetricAlgorithm::Ecc,
            SignatureScheme::Sm2
                .try_into()
                .expect("Failed to convert Sm2 into asymmetric algorithm")
        );

        if AsymmetricAlgorithm::try_from(SignatureScheme::Hmac).is_ok() {
            panic!("It should not be possible to convert Hmac into an asymmetric algorithm");
        }

        // TODO: Change this if Null should be able to be converted into
        // an asymmetric algorithm
        if AsymmetricAlgorithm::try_from(SignatureScheme::Null).is_ok() {
            panic!("It should not be possible to convert Null into an asymmetric algorithm");
        }
    }
}

mod test_symmetric_object_interface_type {
    use super::*;
    use tss_esapi::{
        constants::{
            tss::{TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_NULL, TPM2_ALG_SM4, TPM2_ALG_TDES},
            Algorithm,
        },
        interface_types::algorithm::SymmetricObject,
    };
    #[test]
    fn test_symmetric_object_conversion() {
        test_conversion!(TPM2_ALG_TDES, SymmetricObject::Tdes);
        test_conversion!(TPM2_ALG_AES, SymmetricObject::Aes);
        test_conversion!(TPM2_ALG_SM4, SymmetricObject::Sm4);
        test_conversion!(TPM2_ALG_CAMELLIA, SymmetricObject::Camellia);
        test_conversion!(TPM2_ALG_NULL, SymmetricObject::Null);
    }
}
