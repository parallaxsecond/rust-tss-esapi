// // Copyright 2020 Contributors to the Parsec project.
// // SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tss::{
        TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_CMAC, TPM2_ALG_CTR,
        TPM2_ALG_ECB, TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH, TPM2_ALG_ECDSA, TPM2_ALG_ECMQV,
        TPM2_ALG_ECSCHNORR, TPM2_ALG_ERROR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
        TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
        TPM2_ALG_OAEP, TPM2_ALG_OFB, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS,
        TPM2_ALG_RSASSA, TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256,
        TPM2_ALG_SHA3_384, TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM2, TPM2_ALG_SM3_256,
        TPM2_ALG_SM4, TPM2_ALG_SYMCIPHER, TPM2_ALG_TDES, TPM2_ALG_XOR,
    },
    tss2_esys::TPM2_ALG_ID,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::TryFrom;
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    Error,
    Rsa,
    Tdes,
    // Sha, same as sha1
    Sha1,
    Hmac,
    Aes,
    Mgf1,
    KeyedHash,
    Xor,
    Sha256,
    Sha384,
    Sha512,
    Null,
    Sm3_256,
    Sm4,
    RsaSsa,
    RsaEs,
    RsaPss,
    Oaep,
    EcDsa,
    EcDh,
    EcDaa,
    Sm2,
    EcSchnorr,
    EcMqv,
    Kdf1Sp800_56a,
    Kdf2,
    Kdf1Sp800_108,
    Ecc,
    SymCipher,
    Camellia,
    Cmac,
    Ctr,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Ofb,
    Cbc,
    Cfb,
    Ecb,
}

impl TryFrom<TPM2_ALG_ID> for Algorithm {
    type Error = Error;
    fn try_from(tpm_alg_id: TPM2_ALG_ID) -> Result<Algorithm> {
        match tpm_alg_id {
            TPM2_ALG_AES => Ok(Algorithm::Aes),
            TPM2_ALG_CAMELLIA => Ok(Algorithm::Camellia),
            TPM2_ALG_CBC => Ok(Algorithm::Cbc),
            TPM2_ALG_CFB => Ok(Algorithm::Cfb),
            TPM2_ALG_CMAC => Ok(Algorithm::Cmac),
            TPM2_ALG_CTR => Ok(Algorithm::Ctr),
            TPM2_ALG_ECB => Ok(Algorithm::Ecb),
            TPM2_ALG_ECC => Ok(Algorithm::Ecc),
            TPM2_ALG_ECDAA => Ok(Algorithm::EcDaa),
            TPM2_ALG_ECDH => Ok(Algorithm::EcDh),
            TPM2_ALG_ECDSA => Ok(Algorithm::EcDsa),
            TPM2_ALG_ECMQV => Ok(Algorithm::EcMqv),
            TPM2_ALG_ECSCHNORR => Ok(Algorithm::EcSchnorr),
            TPM2_ALG_ERROR => Ok(Algorithm::Error),
            TPM2_ALG_HMAC => Ok(Algorithm::Hmac),
            TPM2_ALG_KDF1_SP800_108 => Ok(Algorithm::Kdf1Sp800_108),
            TPM2_ALG_KDF1_SP800_56A => Ok(Algorithm::Kdf1Sp800_56a),
            TPM2_ALG_KDF2 => Ok(Algorithm::Kdf2),
            TPM2_ALG_KEYEDHASH => Ok(Algorithm::KeyedHash),
            TPM2_ALG_MGF1 => Ok(Algorithm::Mgf1),
            TPM2_ALG_NULL => Ok(Algorithm::Null),
            TPM2_ALG_OAEP => Ok(Algorithm::Oaep),
            TPM2_ALG_OFB => Ok(Algorithm::Ofb),
            TPM2_ALG_RSA => Ok(Algorithm::Rsa),
            TPM2_ALG_RSAES => Ok(Algorithm::RsaEs),
            TPM2_ALG_RSAPSS => Ok(Algorithm::RsaPss),
            TPM2_ALG_RSASSA => Ok(Algorithm::RsaSsa),
            TPM2_ALG_SHA1 => Ok(Algorithm::Sha1),
            TPM2_ALG_SHA256 => Ok(Algorithm::Sha256),
            TPM2_ALG_SHA384 => Ok(Algorithm::Sha384),
            TPM2_ALG_SHA3_256 => Ok(Algorithm::Sha3_256),
            TPM2_ALG_SHA3_384 => Ok(Algorithm::Sha3_384),
            TPM2_ALG_SHA3_512 => Ok(Algorithm::Sha3_512),
            TPM2_ALG_SHA512 => Ok(Algorithm::Sha512),
            TPM2_ALG_SM2 => Ok(Algorithm::Sm2),
            TPM2_ALG_SM3_256 => Ok(Algorithm::Sm3_256),
            TPM2_ALG_SM4 => Ok(Algorithm::Sm4),
            TPM2_ALG_SYMCIPHER => Ok(Algorithm::SymCipher),
            TPM2_ALG_TDES => Ok(Algorithm::Tdes),
            TPM2_ALG_XOR => Ok(Algorithm::Xor),
            _ => {
                error!("Encounted an unknown TPM2_ALG_ID");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

impl From<Algorithm> for TPM2_ALG_ID {
    fn from(algorithm: Algorithm) -> TPM2_ALG_ID {
        match algorithm {
            Algorithm::Aes => TPM2_ALG_AES,
            Algorithm::Camellia => TPM2_ALG_CAMELLIA,
            Algorithm::Cbc => TPM2_ALG_CBC,
            Algorithm::Cfb => TPM2_ALG_CFB,
            Algorithm::Ctr => TPM2_ALG_CTR,
            Algorithm::Ecb => TPM2_ALG_ECB,
            Algorithm::Ecc => TPM2_ALG_ECC,
            Algorithm::EcDaa => TPM2_ALG_ECDAA,
            Algorithm::EcDh => TPM2_ALG_ECDH,
            Algorithm::EcDsa => TPM2_ALG_ECDSA,
            Algorithm::EcMqv => TPM2_ALG_ECMQV,
            Algorithm::EcSchnorr => TPM2_ALG_ECSCHNORR,
            Algorithm::Error => TPM2_ALG_ERROR,
            Algorithm::Hmac => TPM2_ALG_HMAC,
            Algorithm::Kdf1Sp800_108 => TPM2_ALG_KDF1_SP800_108,
            Algorithm::Kdf1Sp800_56a => TPM2_ALG_KDF1_SP800_56A,
            Algorithm::Kdf2 => TPM2_ALG_KDF2,
            Algorithm::KeyedHash => TPM2_ALG_KEYEDHASH,
            Algorithm::Mgf1 => TPM2_ALG_MGF1,
            Algorithm::Null => TPM2_ALG_NULL,
            Algorithm::Oaep => TPM2_ALG_OAEP,
            Algorithm::Ofb => TPM2_ALG_OFB,
            Algorithm::Rsa => TPM2_ALG_RSA,
            Algorithm::RsaEs => TPM2_ALG_RSAES,
            Algorithm::RsaPss => TPM2_ALG_RSAPSS,
            Algorithm::RsaSsa => TPM2_ALG_RSASSA,
            Algorithm::Sha1 => TPM2_ALG_SHA1,
            Algorithm::Sha256 => TPM2_ALG_SHA256,
            Algorithm::Sha384 => TPM2_ALG_SHA384,
            Algorithm::Sha3_256 => TPM2_ALG_SHA3_256,
            Algorithm::Sha3_384 => TPM2_ALG_SHA3_384,
            Algorithm::Sha3_512 => TPM2_ALG_SHA3_512,
            Algorithm::Sha512 => TPM2_ALG_SHA512,
            Algorithm::Sm2 => TPM2_ALG_SM2,
            Algorithm::Sm3_256 => TPM2_ALG_SM3_256,
            Algorithm::Sm4 => TPM2_ALG_SM4,
            Algorithm::SymCipher => TPM2_ALG_SYMCIPHER,
            Algorithm::Tdes => TPM2_ALG_TDES,
            Algorithm::Xor => TPM2_ALG_XOR,
            Algorithm::Cmac => TPM2_ALG_CMAC,
        }
    }
}

// use crate::tss2_esys::{
//     TPM2_ALG_ID, TPMI_ECC_CURVE, TPMS_SYMCIPHER_PARMS, TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT,
// };
// use crate::utils::TpmtSymDefBuilder;
// use crate::{Error, Result, WrapperErrorKind};
// use std::convert::{From, TryFrom};

// ////////////////////////////////////////////////
// ///
// /// Object Types
// ///
// ////////////////////////////////////////////////

// /// Enum containing object types form the
// /// TPM2 Library Specification.
// /// These are typically
// /// used when setting the type parameter in
// /// TPMT_PUBLIC_PARMS.

// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum ObjectType {
//     Null,
//     Rsa,
//     Ecc,
//     KeyedHash,
//     SymCipher,
// }

// impl From<ObjectType> for TPM2_ALG_ID {
//     fn from(object_type: ObjectType) -> Self {
//         match object_type {
//             ObjectType::Null => TPM2_ALG_NULL,
//             ObjectType::Rsa => TPM2_ALG_RSA,
//             ObjectType::Ecc => TPM2_ALG_ECC,
//             ObjectType::KeyedHash => TPM2_ALG_KEYEDHASH,
//             ObjectType::SymCipher => TPM2_ALG_SYMCIPHER,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for ObjectType {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_NULL => Ok(ObjectType::Null),
//             TPM2_ALG_RSA => Ok(ObjectType::Rsa),
//             TPM2_ALG_ECC => Ok(ObjectType::Ecc),
//             TPM2_ALG_KEYEDHASH => Ok(ObjectType::KeyedHash),
//             TPM2_ALG_SYMCIPHER => Ok(ObjectType::SymCipher),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Asymmetric algorithms.
// ///
// /// The specification specifies these as
// /// "asymmetric algorithm with a public and private key".
// ////////////////////////////////////////////////

// /// Enum containing asymmetric algorithms.
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum AsymmetricAlgorithm {
//     Rsa,
//     Ecc,
// }

// impl From<AsymmetricAlgorithm> for TPM2_ALG_ID {
//     fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
//         match asymmetric_algorithm {
//             AsymmetricAlgorithm::Rsa => TPM2_ALG_RSA,
//             AsymmetricAlgorithm::Ecc => TPM2_ALG_ECC,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for AsymmetricAlgorithm {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_RSA => Ok(AsymmetricAlgorithm::Rsa),
//             TPM2_ALG_ECC => Ok(AsymmetricAlgorithm::Ecc),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Keyed hash (KEYEDHASH)
// ///
// ////////////////////////////////////////////////

// /// Enum containing keyed hash
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum KeyedHash {
//     Hmac,
//     Xor,
// }

// impl KeyedHash {
//     /// Returns the TPM2_ALG_ID that corresponds to the
//     /// keyed hash.
//     pub fn alg_id(self) -> TPM2_ALG_ID {
//         match self {
//             KeyedHash::Hmac => TPM2_ALG_HMAC,
//             KeyedHash::Xor => TPM2_ALG_XOR,
//         }
//     }
// }

// impl From<KeyedHash> for TPM2_ALG_ID {
//     fn from(keyed_hash: KeyedHash) -> Self {
//         match keyed_hash {
//             KeyedHash::Hmac => TPM2_ALG_HMAC,
//             KeyedHash::Xor => TPM2_ALG_XOR,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for KeyedHash {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_HMAC => Ok(KeyedHash::Hmac),
//             TPM2_ALG_XOR => Ok(KeyedHash::Xor),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Symmetric algorithms.(SYMCIPHER)
// ///
// ////////////////////////////////////////////////

// /// Enum containing symmetric algorithms.
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum SymmetricAlgorithm {
//     Aes,
//     Camellia,
//     Sm4,
//     Tdes,
//     Xor,
// }

// impl From<SymmetricAlgorithm> for TPM2_ALG_ID {
//     fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
//         match symmetric_algorithm {
//             SymmetricAlgorithm::Aes => TPM2_ALG_AES,
//             SymmetricAlgorithm::Camellia => TPM2_ALG_CAMELLIA,
//             SymmetricAlgorithm::Sm4 => TPM2_ALG_SM4,
//             SymmetricAlgorithm::Tdes => TPM2_ALG_TDES,
//             SymmetricAlgorithm::Xor => TPM2_ALG_XOR,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for SymmetricAlgorithm {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_AES => Ok(SymmetricAlgorithm::Aes),
//             TPM2_ALG_CAMELLIA => Ok(SymmetricAlgorithm::Camellia),
//             TPM2_ALG_SM4 => Ok(SymmetricAlgorithm::Sm4),
//             TPM2_ALG_TDES => Ok(SymmetricAlgorithm::Tdes),
//             TPM2_ALG_XOR => Ok(SymmetricAlgorithm::Xor),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Hashing Algorithms
// ///
// ////////////////////////////////////////////////

// /// Enum containing the supported hash algorithms
// #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
// pub enum HashingAlgorithm {
//     Sha1,
//     Sha256,
//     Sha384,
//     Sha512,
//     Sm3_256,
//     Sha3_256,
//     Sha3_384,
//     Sha3_512,
// }

// impl From<HashingAlgorithm> for TPM2_ALG_ID {
//     fn from(hashing_algorithm: HashingAlgorithm) -> Self {
//         match hashing_algorithm {
//             HashingAlgorithm::Sha1 => TPM2_ALG_SHA1,
//             HashingAlgorithm::Sha256 => TPM2_ALG_SHA256,
//             HashingAlgorithm::Sha384 => TPM2_ALG_SHA384,
//             HashingAlgorithm::Sha512 => TPM2_ALG_SHA512,
//             HashingAlgorithm::Sm3_256 => TPM2_ALG_SM3_256,
//             HashingAlgorithm::Sha3_256 => TPM2_ALG_SHA3_256,
//             HashingAlgorithm::Sha3_384 => TPM2_ALG_SHA3_384,
//             HashingAlgorithm::Sha3_512 => TPM2_ALG_SHA3_512,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for HashingAlgorithm {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_SHA1 => Ok(HashingAlgorithm::Sha1),
//             TPM2_ALG_SHA256 => Ok(HashingAlgorithm::Sha256),
//             TPM2_ALG_SHA384 => Ok(HashingAlgorithm::Sha384),
//             TPM2_ALG_SHA512 => Ok(HashingAlgorithm::Sha512),
//             TPM2_ALG_SM3_256 => Ok(HashingAlgorithm::Sm3_256),
//             TPM2_ALG_SHA3_256 => Ok(HashingAlgorithm::Sha3_256),
//             TPM2_ALG_SHA3_384 => Ok(HashingAlgorithm::Sha3_384),
//             TPM2_ALG_SHA3_512 => Ok(HashingAlgorithm::Sha3_512),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Signature Schemes
// ///
// ////////////////////////////////////////////////

// /// Enum containing signature schemes
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum SignatureScheme {
//     Rsa(RsaSignatureScheme),
//     Ecc(EccSignatureScheme),
// }

// impl From<SignatureScheme> for TPM2_ALG_ID {
//     fn from(signature_scheme: SignatureScheme) -> Self {
//         match signature_scheme {
//             SignatureScheme::Rsa(ss) => ss.into(),
//             SignatureScheme::Ecc(ss) => ss.into(),
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for SignatureScheme {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_RSASSA => Ok(SignatureScheme::Rsa(RsaSignatureScheme::RsaSsa)),
//             TPM2_ALG_RSAPSS => Ok(SignatureScheme::Rsa(RsaSignatureScheme::RsaPss)),
//             TPM2_ALG_ECDSA => Ok(SignatureScheme::Ecc(EccSignatureScheme::EcDsa)),
//             TPM2_ALG_ECDAA => Ok(SignatureScheme::Ecc(EccSignatureScheme::EcDaa)),
//             TPM2_ALG_ECSCHNORR => Ok(SignatureScheme::Ecc(EccSignatureScheme::EcSchnorr)),
//             TPM2_ALG_SM2 => Ok(SignatureScheme::Ecc(EccSignatureScheme::Sm2)),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// impl SignatureScheme {
//     pub fn get_key_alg(&self) -> AsymmetricAlgorithm {
//         match self {
//             SignatureScheme::Rsa(_) => AsymmetricAlgorithm::Rsa,
//             SignatureScheme::Ecc(_) => AsymmetricAlgorithm::Ecc,
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// RSA Signature Schemes
// ///
// ////////////////////////////////////////////////

// /// Enum containing RSA signature schemes
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum RsaSignatureScheme {
//     RsaSsa,
//     RsaPss,
// }

// impl From<RsaSignatureScheme> for TPM2_ALG_ID {
//     fn from(rsa_signature_scheme: RsaSignatureScheme) -> Self {
//         match rsa_signature_scheme {
//             RsaSignatureScheme::RsaSsa => TPM2_ALG_RSASSA,
//             RsaSignatureScheme::RsaPss => TPM2_ALG_RSAPSS,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for RsaSignatureScheme {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_RSASSA => Ok(RsaSignatureScheme::RsaSsa),
//             TPM2_ALG_RSAPSS => Ok(RsaSignatureScheme::RsaPss),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// ECC Signature Schemes
// ///
// ////////////////////////////////////////////////

// /// Enum containing ECC signature schemes
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum EccSignatureScheme {
//     EcDsa,
//     EcDaa,
//     EcSchnorr,
//     Sm2,
// }

// impl From<EccSignatureScheme> for TPM2_ALG_ID {
//     fn from(ecc_signature_scheme: EccSignatureScheme) -> Self {
//         match ecc_signature_scheme {
//             EccSignatureScheme::EcDsa => TPM2_ALG_ECDSA,
//             EccSignatureScheme::EcDaa => TPM2_ALG_ECDAA,
//             EccSignatureScheme::EcSchnorr => TPM2_ALG_ECSCHNORR,
//             EccSignatureScheme::Sm2 => TPM2_ALG_SM2,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for EccSignatureScheme {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_ECDSA => Ok(EccSignatureScheme::EcDsa),
//             TPM2_ALG_ECDAA => Ok(EccSignatureScheme::EcDaa),
//             TPM2_ALG_ECSCHNORR => Ok(EccSignatureScheme::EcSchnorr),
//             TPM2_ALG_SM2 => Ok(EccSignatureScheme::Sm2),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Asymmetric Encryption Schemes
// ///
// ////////////////////////////////////////////////

// // Enum containing asymmetric encryption schemes
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum AsymmetricEncryptionScheme {
//     Oaep,
//     RsaEs,
//     EcDh, //Elliptic-curve Diffie–Hellman
// }

// impl From<AsymmetricEncryptionScheme> for TPM2_ALG_ID {
//     fn from(asymmetric_encryption_scheme: AsymmetricEncryptionScheme) -> Self {
//         match asymmetric_encryption_scheme {
//             AsymmetricEncryptionScheme::Oaep => TPM2_ALG_OAEP,
//             AsymmetricEncryptionScheme::RsaEs => TPM2_ALG_RSAES,
//             AsymmetricEncryptionScheme::EcDh => TPM2_ALG_ECDH,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for AsymmetricEncryptionScheme {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_OAEP => Ok(AsymmetricEncryptionScheme::Oaep),
//             TPM2_ALG_RSAES => Ok(AsymmetricEncryptionScheme::RsaEs),
//             TPM2_ALG_ECDH => Ok(AsymmetricEncryptionScheme::EcDh),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Encryption Modes
// ///
// ////////////////////////////////////////////////

// // Enum containing encryption modes
// #[derive(Copy, Clone, Debug, PartialEq, Eq)]
// pub enum EncryptionMode {
//     Ctr,
//     Ofb,
//     Cbc,
//     Cfb,
//     Ecb,
// }

// impl From<EncryptionMode> for TPM2_ALG_ID {
//     fn from(encryption_mode: EncryptionMode) -> Self {
//         match encryption_mode {
//             EncryptionMode::Ctr => TPM2_ALG_CTR,
//             EncryptionMode::Ofb => TPM2_ALG_OFB,
//             EncryptionMode::Cbc => TPM2_ALG_CBC,
//             EncryptionMode::Cfb => TPM2_ALG_CFB,
//             EncryptionMode::Ecb => TPM2_ALG_ECB,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for EncryptionMode {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_CTR => Ok(EncryptionMode::Ctr),
//             TPM2_ALG_OFB => Ok(EncryptionMode::Ofb),
//             TPM2_ALG_CBC => Ok(EncryptionMode::Cbc),
//             TPM2_ALG_CFB => Ok(EncryptionMode::Cfb),
//             TPM2_ALG_ECB => Ok(EncryptionMode::Ecb),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Mask Generation Functions
// ///
// ////////////////////////////////////////////////

// // Enum containing mask generation functions.
// #[derive(Copy, Clone, Debug, PartialEq)]
// pub enum MaskGenerationFunction {
//     Mgf1,
// }

// impl From<MaskGenerationFunction> for TPM2_ALG_ID {
//     fn from(mask_generation_function: MaskGenerationFunction) -> Self {
//         match mask_generation_function {
//             MaskGenerationFunction::Mgf1 => TPM2_ALG_MGF1,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for MaskGenerationFunction {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_MGF1 => Ok(MaskGenerationFunction::Mgf1),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }
// ////////////////////////////////////////////////
// ///
// /// Key Derivation Functions
// ///
// ////////////////////////////////////////////////

// // Enum containing key derivation functions.
// #[derive(Copy, Clone, Debug, PartialEq)]
// pub enum KeyDerivationFunction {
//     Kdf1Sp800_56a,
//     Kdf2,
//     Kdf1Sp800_108,
//     EcMqv,
// }

// impl From<KeyDerivationFunction> for TPM2_ALG_ID {
//     fn from(key_derivation_function: KeyDerivationFunction) -> Self {
//         match key_derivation_function {
//             KeyDerivationFunction::Kdf1Sp800_56a => TPM2_ALG_KDF1_SP800_56A,
//             KeyDerivationFunction::Kdf2 => TPM2_ALG_KDF2,
//             KeyDerivationFunction::Kdf1Sp800_108 => TPM2_ALG_KDF1_SP800_108,
//             KeyDerivationFunction::EcMqv => TPM2_ALG_ECMQV,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for KeyDerivationFunction {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_KDF1_SP800_56A => Ok(KeyDerivationFunction::Kdf1Sp800_56a),
//             TPM2_ALG_KDF2 => Ok(KeyDerivationFunction::Kdf2),
//             TPM2_ALG_KDF1_SP800_108 => Ok(KeyDerivationFunction::Kdf1Sp800_108),
//             TPM2_ALG_ECMQV => Ok(KeyDerivationFunction::EcMqv),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }

// ////////////////////////////////////////////////
// ///
// /// Algorithmic Error
// ///
// ////////////////////////////////////////////////

// /// Enum continaing algorithmic errors.
// #[derive(Copy, Clone, Debug, PartialEq)]
// pub enum AlgorithmicError {
//     Error,
// }

// impl From<AlgorithmicError> for TPM2_ALG_ID {
//     fn from(algorithmic_error: AlgorithmicError) -> Self {
//         match algorithmic_error {
//             AlgorithmicError::Error => TPM2_ALG_ERROR,
//         }
//     }
// }

// impl TryFrom<TPM2_ALG_ID> for AlgorithmicError {
//     type Error = Error;

//     fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
//         match algorithm_id {
//             TPM2_ALG_ERROR => Ok(AlgorithmicError::Error),
//             _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
//         }
//     }
// }
