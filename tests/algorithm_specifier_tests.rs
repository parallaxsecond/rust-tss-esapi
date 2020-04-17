// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::constants::*;
use tss_esapi::tss2_esys::TPM2_ALG_ID;
use tss_esapi::utils::algorithm_specifiers::*;

mod test_object_type {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(Into::<TPM2_ALG_ID>::into(ObjectType::Null), TPM2_ALG_NULL);
        assert_eq!(Into::<TPM2_ALG_ID>::into(ObjectType::Rsa), TPM2_ALG_RSA);
        assert_eq!(Into::<TPM2_ALG_ID>::into(ObjectType::Ecc), TPM2_ALG_ECC);
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(ObjectType::KeyedHash),
            TPM2_ALG_KEYEDHASH
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(ObjectType::SymCipher),
            TPM2_ALG_SYMCIPHER
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            ObjectType::try_from(TPM2_ALG_NULL).unwrap(),
            ObjectType::Null
        );
        assert_eq!(ObjectType::try_from(TPM2_ALG_RSA).unwrap(), ObjectType::Rsa);
        assert_eq!(ObjectType::try_from(TPM2_ALG_ECC).unwrap(), ObjectType::Ecc);
        assert_eq!(
            ObjectType::try_from(TPM2_ALG_KEYEDHASH).unwrap(),
            ObjectType::KeyedHash
        );
        assert_eq!(
            ObjectType::try_from(TPM2_ALG_SYMCIPHER).unwrap(),
            ObjectType::SymCipher
        );
        assert!(
            ObjectType::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in ObjectType"
        );
    }
}

mod test_asymmetric_algorithm {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AsymmetricAlgorithm::Rsa),
            TPM2_ALG_RSA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AsymmetricAlgorithm::Ecc),
            TPM2_ALG_ECC
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            AsymmetricAlgorithm::try_from(TPM2_ALG_RSA).unwrap(),
            AsymmetricAlgorithm::Rsa
        );
        assert_eq!(
            AsymmetricAlgorithm::try_from(TPM2_ALG_ECC).unwrap(),
            AsymmetricAlgorithm::Ecc
        );
        assert!(
            AsymmetricAlgorithm::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in AsymmetricAlgorithm"
        );
    }
}

mod test_keyed_hash {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(Into::<TPM2_ALG_ID>::into(KeyedHash::Hmac), TPM2_ALG_HMAC);
        assert_eq!(Into::<TPM2_ALG_ID>::into(KeyedHash::Xor), TPM2_ALG_XOR);
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(KeyedHash::try_from(TPM2_ALG_HMAC).unwrap(), KeyedHash::Hmac);
        assert_eq!(KeyedHash::try_from(TPM2_ALG_XOR).unwrap(), KeyedHash::Xor);
        assert!(
            KeyedHash::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in KeyedHash"
        );
    }
}

mod test_symmetric_algorithm {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SymmetricAlgorithm::Aes),
            TPM2_ALG_AES
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SymmetricAlgorithm::Camellia),
            TPM2_ALG_CAMELLIA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SymmetricAlgorithm::Sm4),
            TPM2_ALG_SM4
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            SymmetricAlgorithm::try_from(TPM2_ALG_AES).unwrap(),
            SymmetricAlgorithm::Aes
        );
        assert_eq!(
            SymmetricAlgorithm::try_from(TPM2_ALG_CAMELLIA).unwrap(),
            SymmetricAlgorithm::Camellia
        );
        assert_eq!(
            SymmetricAlgorithm::try_from(TPM2_ALG_SM4).unwrap(),
            SymmetricAlgorithm::Sm4
        );
        assert!(
            SymmetricAlgorithm::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in SymmetricAlgorithm"
        );
    }
}

mod test_hashing_algorithm {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha1),
            TPM2_ALG_SHA1
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha256),
            TPM2_ALG_SHA256
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha384),
            TPM2_ALG_SHA384
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha512),
            TPM2_ALG_SHA512
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sm3_256),
            TPM2_ALG_SM3_256
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha3_256),
            TPM2_ALG_SHA3_256
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha3_384),
            TPM2_ALG_SHA3_384
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha3_512),
            TPM2_ALG_SHA3_512
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA1).unwrap(),
            HashingAlgorithm::Sha1
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA256).unwrap(),
            HashingAlgorithm::Sha256
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA384).unwrap(),
            HashingAlgorithm::Sha384
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA512).unwrap(),
            HashingAlgorithm::Sha512
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SM3_256).unwrap(),
            HashingAlgorithm::Sm3_256
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA3_256).unwrap(),
            HashingAlgorithm::Sha3_256
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA3_384).unwrap(),
            HashingAlgorithm::Sha3_384
        );
        assert_eq!(
            HashingAlgorithm::try_from(TPM2_ALG_SHA3_512).unwrap(),
            HashingAlgorithm::Sha3_512
        );
        assert!(
            HashingAlgorithm::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in HashingAlgorithm"
        );
    }
}

mod test_signature_scheme {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::RsaSsa),
            TPM2_ALG_RSASSA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::RsaPss),
            TPM2_ALG_RSAPSS
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::EcDsa),
            TPM2_ALG_ECDSA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::EcDaa),
            TPM2_ALG_ECDAA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::EcSchnorr),
            TPM2_ALG_ECSCHNORR
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(SignatureScheme::Sm2),
            TPM2_ALG_SM2
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_RSASSA).unwrap(),
            SignatureScheme::RsaSsa
        );
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_RSAPSS).unwrap(),
            SignatureScheme::RsaPss
        );
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_ECDSA).unwrap(),
            SignatureScheme::EcDsa
        );
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_ECDAA).unwrap(),
            SignatureScheme::EcDaa
        );
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_ECSCHNORR).unwrap(),
            SignatureScheme::EcSchnorr
        );
        assert_eq!(
            SignatureScheme::try_from(TPM2_ALG_SM2).unwrap(),
            SignatureScheme::Sm2
        );
        assert!(
            SignatureScheme::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in SignatureScheme"
        );
    }
}

mod test_rsa_signature_scheme {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(RsaSignatureScheme::RsaPss),
            TPM2_ALG_RSAPSS
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(RsaSignatureScheme::RsaSsa),
            TPM2_ALG_RSASSA
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            RsaSignatureScheme::try_from(TPM2_ALG_RSASSA).unwrap(),
            RsaSignatureScheme::RsaSsa
        );
        assert_eq!(
            RsaSignatureScheme::try_from(TPM2_ALG_RSAPSS).unwrap(),
            RsaSignatureScheme::RsaPss
        );
        assert!(
            RsaSignatureScheme::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in RsaSignatureScheme"
        );
    }
}

mod test_ecc_signature_scheme {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(EccSignatureScheme::EcDsa),
            TPM2_ALG_ECDSA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(EccSignatureScheme::EcDaa),
            TPM2_ALG_ECDAA
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(EccSignatureScheme::EcSchnorr),
            TPM2_ALG_ECSCHNORR
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(EccSignatureScheme::Sm2),
            TPM2_ALG_SM2
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            EccSignatureScheme::try_from(TPM2_ALG_ECDSA).unwrap(),
            EccSignatureScheme::EcDsa
        );
        assert_eq!(
            EccSignatureScheme::try_from(TPM2_ALG_ECDAA).unwrap(),
            EccSignatureScheme::EcDaa
        );
        assert_eq!(
            EccSignatureScheme::try_from(TPM2_ALG_ECSCHNORR).unwrap(),
            EccSignatureScheme::EcSchnorr
        );
        assert_eq!(
            EccSignatureScheme::try_from(TPM2_ALG_SM2).unwrap(),
            EccSignatureScheme::Sm2
        );
        assert!(
            EccSignatureScheme::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in EccSignatureScheme"
        );
    }
}

mod test_asymmetric_encrytion_scheme {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AsymmetricEncryptionScheme::Oaep),
            TPM2_ALG_OAEP
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AsymmetricEncryptionScheme::RsaEs),
            TPM2_ALG_RSAES
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AsymmetricEncryptionScheme::EcDh),
            TPM2_ALG_ECDH
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            AsymmetricEncryptionScheme::try_from(TPM2_ALG_OAEP).unwrap(),
            AsymmetricEncryptionScheme::Oaep
        );
        assert_eq!(
            AsymmetricEncryptionScheme::try_from(TPM2_ALG_RSAES).unwrap(),
            AsymmetricEncryptionScheme::RsaEs
        );
        assert_eq!(
            AsymmetricEncryptionScheme::try_from(TPM2_ALG_ECDH).unwrap(),
            AsymmetricEncryptionScheme::EcDh
        );
        assert!(
            AsymmetricEncryptionScheme::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in AsymmetricEncryptionScheme"
        );
    }
}

mod test_encryption_mode {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(Into::<TPM2_ALG_ID>::into(EncryptionMode::Ctr), TPM2_ALG_CTR);
        assert_eq!(Into::<TPM2_ALG_ID>::into(EncryptionMode::Ofb), TPM2_ALG_OFB);
        assert_eq!(Into::<TPM2_ALG_ID>::into(EncryptionMode::Cbc), TPM2_ALG_CBC);
        assert_eq!(Into::<TPM2_ALG_ID>::into(EncryptionMode::Cfb), TPM2_ALG_CFB);
        assert_eq!(Into::<TPM2_ALG_ID>::into(EncryptionMode::Ecb), TPM2_ALG_ECB);
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            EncryptionMode::try_from(TPM2_ALG_CTR).unwrap(),
            EncryptionMode::Ctr
        );
        assert_eq!(
            EncryptionMode::try_from(TPM2_ALG_OFB).unwrap(),
            EncryptionMode::Ofb
        );
        assert_eq!(
            EncryptionMode::try_from(TPM2_ALG_CBC).unwrap(),
            EncryptionMode::Cbc
        );
        assert_eq!(
            EncryptionMode::try_from(TPM2_ALG_CFB).unwrap(),
            EncryptionMode::Cfb
        );
        assert_eq!(
            EncryptionMode::try_from(TPM2_ALG_ECB).unwrap(),
            EncryptionMode::Ecb
        );
        assert!(
            EncryptionMode::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in EncryptionMode"
        );
    }
}

mod test_mask_generation_function {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(MaskGenerationFunction::Mgf1),
            TPM2_ALG_MGF1
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            MaskGenerationFunction::try_from(TPM2_ALG_MGF1).unwrap(),
            MaskGenerationFunction::Mgf1
        );
        assert!(
            MaskGenerationFunction::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in MaskGenerationFunction"
        );
    }
}

mod test_key_derivation_function {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(KeyDerivationFunction::Kdf1Sp800_56a),
            TPM2_ALG_KDF1_SP800_56A
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(KeyDerivationFunction::Kdf2),
            TPM2_ALG_KDF2
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(KeyDerivationFunction::Kdf1Sp800_108),
            TPM2_ALG_KDF1_SP800_108
        );
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(KeyDerivationFunction::EcMqv),
            TPM2_ALG_ECMQV
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            KeyDerivationFunction::try_from(TPM2_ALG_KDF1_SP800_56A).unwrap(),
            KeyDerivationFunction::Kdf1Sp800_56a
        );
        assert_eq!(
            KeyDerivationFunction::try_from(TPM2_ALG_KDF2).unwrap(),
            KeyDerivationFunction::Kdf2
        );
        assert_eq!(
            KeyDerivationFunction::try_from(TPM2_ALG_KDF1_SP800_108).unwrap(),
            KeyDerivationFunction::Kdf1Sp800_108
        );
        assert_eq!(
            KeyDerivationFunction::try_from(TPM2_ALG_ECMQV).unwrap(),
            KeyDerivationFunction::EcMqv
        );
        assert!(
            EncryptionMode::try_from(TPM2_ALG_ERROR).is_err(),
            "Error should not exist in KeyDerivationFunction"
        );
    }
}

mod test_algorithmic_error {
    use super::*;

    #[test]
    fn test_into_alogithm_id() {
        assert_eq!(
            Into::<TPM2_ALG_ID>::into(AlgorithmicError::Error),
            TPM2_ALG_ERROR
        );
    }

    #[test]
    fn test_try_from_alogithm_id() {
        assert_eq!(
            AlgorithmicError::try_from(TPM2_ALG_ERROR).unwrap(),
            AlgorithmicError::Error
        );
    }
}
