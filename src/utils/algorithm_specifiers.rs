// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Algorithm Specifier Module
//!
//! This module specifies the different algorithms and
//! provides function for converting them to their corresponding
//! TPM2_ALG_ID
//!
//! TPM 2.0 Library Specification(Rev: 1.59), Part 2, Secion 6.3, Table 8 — Legend for TPM_ALG_ID Table

use crate::constants::{
    TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_CTR, TPM2_ALG_ECB,
    TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH, TPM2_ALG_ECDSA, TPM2_ALG_ECMQV,
    TPM2_ALG_ECSCHNORR, TPM2_ALG_ERROR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
    TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
    TPM2_ALG_OAEP, TPM2_ALG_OFB, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS, TPM2_ALG_RSASSA,
    TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256, TPM2_ALG_SHA3_384,
    TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM2, TPM2_ALG_SM3_256, TPM2_ALG_SM4,
    TPM2_ALG_SYMCIPHER, TPM2_ALG_XOR,
};

use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2_ALG_ID;
use std::convert::TryFrom;

////////////////////////////////////////////////
///
/// Object Types
///
////////////////////////////////////////////////

/// Enum containing object types form the
/// TPM2 Library Specification.
/// These are typically
/// used when setting the type parameter in
/// TPMT_PUBLIC_PARMS.

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ObjectType {
    Null,
    Rsa,
    Ecc,
    KeyedHash,
    SymCipher,
}

impl ObjectType {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// object type.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            ObjectType::Null => TPM2_ALG_NULL,
            ObjectType::Rsa => TPM2_ALG_RSA,
            ObjectType::Ecc => TPM2_ALG_ECC,
            ObjectType::KeyedHash => TPM2_ALG_KEYEDHASH,
            ObjectType::SymCipher => TPM2_ALG_SYMCIPHER,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for ObjectType {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_NULL => Ok(ObjectType::Null),
            TPM2_ALG_RSA => Ok(ObjectType::Rsa),
            TPM2_ALG_ECC => Ok(ObjectType::Ecc),
            TPM2_ALG_KEYEDHASH => Ok(ObjectType::KeyedHash),
            TPM2_ALG_SYMCIPHER => Ok(ObjectType::SymCipher),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Asymmetric algorithms.
///
/// The specification specifies these as
/// "asymmetric algorithm with a public and private key".
////////////////////////////////////////////////

/// Enum containing asymmetric algorithms.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricAlgorithm {
    Rsa,
    Ecc,
}

impl AsymmetricAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// asymmetric algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AsymmetricAlgorithm::Rsa => TPM2_ALG_RSA,
            AsymmetricAlgorithm::Ecc => TPM2_ALG_ECC,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AsymmetricAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSA => Ok(AsymmetricAlgorithm::Rsa),
            TPM2_ALG_ECC => Ok(AsymmetricAlgorithm::Ecc),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Keyed hash (KEYEDHASH)
///
////////////////////////////////////////////////

/// Enum containing keyed hash
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyedHash {
    Hmac,
    Xor,
}

impl KeyedHash {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// keyed hash.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            KeyedHash::Hmac => TPM2_ALG_HMAC,
            KeyedHash::Xor => TPM2_ALG_XOR,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for KeyedHash {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_HMAC => Ok(KeyedHash::Hmac),
            TPM2_ALG_XOR => Ok(KeyedHash::Xor),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Symmetric algorithms.(SYMCIPHER)
///
////////////////////////////////////////////////

/// Enum containing symmetric algorithms.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SymmetricAlgorithm {
    Aes,
    Camellia,
    Sm4,
}

impl SymmetricAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// symmetric algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            SymmetricAlgorithm::Aes => TPM2_ALG_AES,
            SymmetricAlgorithm::Camellia => TPM2_ALG_CAMELLIA,
            SymmetricAlgorithm::Sm4 => TPM2_ALG_SM4,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for SymmetricAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_AES => Ok(SymmetricAlgorithm::Aes),
            TPM2_ALG_CAMELLIA => Ok(SymmetricAlgorithm::Camellia),
            TPM2_ALG_SM4 => Ok(SymmetricAlgorithm::Sm4),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Hashing Algorithms
///
////////////////////////////////////////////////

/// Enum containing the supported hash algorithms
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HashingAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl HashingAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// hash algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            HashingAlgorithm::Sha1 => TPM2_ALG_SHA1,
            HashingAlgorithm::Sha256 => TPM2_ALG_SHA256,
            HashingAlgorithm::Sha384 => TPM2_ALG_SHA384,
            HashingAlgorithm::Sha512 => TPM2_ALG_SHA512,
            HashingAlgorithm::Sm3_256 => TPM2_ALG_SM3_256,
            HashingAlgorithm::Sha3_256 => TPM2_ALG_SHA3_256,
            HashingAlgorithm::Sha3_384 => TPM2_ALG_SHA3_384,
            HashingAlgorithm::Sha3_512 => TPM2_ALG_SHA3_512,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for HashingAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_SHA1 => Ok(HashingAlgorithm::Sha1),
            TPM2_ALG_SHA256 => Ok(HashingAlgorithm::Sha256),
            TPM2_ALG_SHA384 => Ok(HashingAlgorithm::Sha384),
            TPM2_ALG_SHA512 => Ok(HashingAlgorithm::Sha512),
            TPM2_ALG_SM3_256 => Ok(HashingAlgorithm::Sm3_256),
            TPM2_ALG_SHA3_256 => Ok(HashingAlgorithm::Sha3_256),
            TPM2_ALG_SHA3_384 => Ok(HashingAlgorithm::Sha3_384),
            TPM2_ALG_SHA3_512 => Ok(HashingAlgorithm::Sha3_512),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing signature schemes
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum SignatureScheme {
    RsaSsa,
    RsaPss,
    EcDsa,
    EcDaa,
    EcSchnorr,
    Sm2,
}

impl SignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// signature scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            SignatureScheme::RsaSsa => TPM2_ALG_RSASSA,
            SignatureScheme::RsaPss => TPM2_ALG_RSAPSS,
            SignatureScheme::EcDsa => TPM2_ALG_ECDSA,
            SignatureScheme::EcDaa => TPM2_ALG_ECDAA,
            SignatureScheme::EcSchnorr => TPM2_ALG_ECSCHNORR,
            SignatureScheme::Sm2 => TPM2_ALG_SM2,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for SignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSASSA => Ok(SignatureScheme::RsaSsa),
            TPM2_ALG_RSAPSS => Ok(SignatureScheme::RsaPss),
            TPM2_ALG_ECDSA => Ok(SignatureScheme::EcDsa),
            TPM2_ALG_ECDAA => Ok(SignatureScheme::EcDaa),
            TPM2_ALG_ECSCHNORR => Ok(SignatureScheme::EcSchnorr),
            TPM2_ALG_SM2 => Ok(SignatureScheme::Sm2),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// RSA Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing RSA signature schemes
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum RsaSignatureScheme {
    RsaSsa,
    RsaPss,
}

impl RsaSignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// RSA signature scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            RsaSignatureScheme::RsaSsa => TPM2_ALG_RSASSA,
            RsaSignatureScheme::RsaPss => TPM2_ALG_RSAPSS,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for RsaSignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSASSA => Ok(RsaSignatureScheme::RsaSsa),
            TPM2_ALG_RSAPSS => Ok(RsaSignatureScheme::RsaPss),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// ECC Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing ECC signature schemes
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EccSignatureScheme {
    EcDsa,
    EcDaa,
    EcSchnorr,
    Sm2,
}

impl EccSignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// signing scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            EccSignatureScheme::EcDsa => TPM2_ALG_ECDSA,
            EccSignatureScheme::EcDaa => TPM2_ALG_ECDAA,
            EccSignatureScheme::EcSchnorr => TPM2_ALG_ECSCHNORR,
            EccSignatureScheme::Sm2 => TPM2_ALG_SM2,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for EccSignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_ECDSA => Ok(EccSignatureScheme::EcDsa),
            TPM2_ALG_ECDAA => Ok(EccSignatureScheme::EcDaa),
            TPM2_ALG_ECSCHNORR => Ok(EccSignatureScheme::EcSchnorr),
            TPM2_ALG_SM2 => Ok(EccSignatureScheme::Sm2),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Asymmetric Encryption Schemes
///
////////////////////////////////////////////////

// Enum containing asymmetric encryption schemes
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AsymmetricEncryptionScheme {
    Oaep,
    RsaEs,
    EcDh, //Elliptic-curve Diffie–Hellman
}

impl AsymmetricEncryptionScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// asymmetric encryption scheme.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AsymmetricEncryptionScheme::Oaep => TPM2_ALG_OAEP,
            AsymmetricEncryptionScheme::RsaEs => TPM2_ALG_RSAES,
            AsymmetricEncryptionScheme::EcDh => TPM2_ALG_ECDH,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AsymmetricEncryptionScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_OAEP => Ok(AsymmetricEncryptionScheme::Oaep),
            TPM2_ALG_RSAES => Ok(AsymmetricEncryptionScheme::RsaEs),
            TPM2_ALG_ECDH => Ok(AsymmetricEncryptionScheme::EcDh),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Encryption Modes
///
////////////////////////////////////////////////

// Enum containing encryption modes
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum EncryptionMode {
    Ctr,
    Ofb,
    Cbc,
    Cfb,
    Ecb,
}

impl EncryptionMode {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// encryption mode.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            EncryptionMode::Ctr => TPM2_ALG_CTR,
            EncryptionMode::Ofb => TPM2_ALG_OFB,
            EncryptionMode::Cbc => TPM2_ALG_CBC,
            EncryptionMode::Cfb => TPM2_ALG_CFB,
            EncryptionMode::Ecb => TPM2_ALG_ECB,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for EncryptionMode {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_CTR => Ok(EncryptionMode::Ctr),
            TPM2_ALG_OFB => Ok(EncryptionMode::Ofb),
            TPM2_ALG_CBC => Ok(EncryptionMode::Cbc),
            TPM2_ALG_CFB => Ok(EncryptionMode::Cfb),
            TPM2_ALG_ECB => Ok(EncryptionMode::Ecb),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Mask Generation Functions
///
////////////////////////////////////////////////

// Enum containing mask generation functions.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MaskGenerationFunction {
    Mgf1,
}

impl MaskGenerationFunction {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// mask generation function.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            MaskGenerationFunction::Mgf1 => TPM2_ALG_MGF1,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for MaskGenerationFunction {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_MGF1 => Ok(MaskGenerationFunction::Mgf1),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
////////////////////////////////////////////////
///
/// Key Derivation Functions
///
////////////////////////////////////////////////

// Enum containing key derivation functions.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyDerivationFunction {
    Kdf1Sp800_56a,
    Kdf2,
    Kdf1Sp800_108,
    EcMqv,
}

impl KeyDerivationFunction {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// key derivation function.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            KeyDerivationFunction::Kdf1Sp800_56a => TPM2_ALG_KDF1_SP800_56A,
            KeyDerivationFunction::Kdf2 => TPM2_ALG_KDF2,
            KeyDerivationFunction::Kdf1Sp800_108 => TPM2_ALG_KDF1_SP800_108,
            KeyDerivationFunction::EcMqv => TPM2_ALG_ECMQV,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_KDF1_SP800_56A => Ok(KeyDerivationFunction::Kdf1Sp800_56a),
            TPM2_ALG_KDF2 => Ok(KeyDerivationFunction::Kdf2),
            TPM2_ALG_KDF1_SP800_108 => Ok(KeyDerivationFunction::Kdf1Sp800_108),
            TPM2_ALG_ECMQV => Ok(KeyDerivationFunction::EcMqv),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

////////////////////////////////////////////////
///
/// Algorithmic Error
///
////////////////////////////////////////////////

/// Enum continaing algorithmic errors.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum AlgorithmicError {
    Error,
}

impl AlgorithmicError {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// algorithmic error.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AlgorithmicError::Error => TPM2_ALG_ERROR,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AlgorithmicError {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_ERROR => Ok(AlgorithmicError::Error),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
