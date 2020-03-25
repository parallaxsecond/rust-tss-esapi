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

//! Module for algorithm specifiers
//!
//! This module specifies the different algorithms and
//! provides function for converting them to their corresponding
//! TPM2_ALG_ID
//!
//! TPM 2.0 Library Specification(Rev: 1.59), Part 2, Secion 6.3, Table 8 — Legend for TPM_ALG_ID Table

pub mod constants::{
    TPM2_ALG_ERROR,
    TPM2_ALG_RSA,
    TPM2_ALG_SHA,/// Does not seam to be used any where!
    TPM2_ALG_SHA1,
    TPM2_ALG_HMAC,
    TPM2_ALG_AES,
    TPM2_ALG_MGF1,
    TPM2_ALG_KEYEDHASH,
    TPM2_ALG_XOR,
    TPM2_ALG_SHA256,
    TPM2_ALG_SHA384,
    TPM2_ALG_SHA512,
    TPM2_ALG_NULL,
    TPM2_ALG_SM3_256,
    TPM2_ALG_SM4,
    TPM2_ALG_RSASSA,
    TPM2_ALG_RSAES,
    TPM2_ALG_RSAPSS,
    TPM2_ALG_OAEP,
    TPM2_ALG_ECDSA,
    TPM2_ALG_ECDH,
    TPM2_ALG_ECDAA,
    TPM2_ALG_SM2,
    TPM2_ALG_ECSCHNORR,
    TPM2_ALG_ECMQV,
    TPM2_ALG_KDF1_SP800_56A,
    TPM2_ALG_KDF2,
    TPM2_ALG_KDF1_SP800_108,
    TPM2_ALG_ECC,
    TPM2_ALG_SYMCIPHER:,
    TPM2_ALG_CAMELLIA,
    TPM2_ALG_CMAC,
    TPM2_ALG_CTR,
    TPM2_ALG_SHA3_256,
    TPM2_ALG_SHA3_384,
    TPM2_ALG_SHA3_512,
    TPM2_ALG_OFB,
    TPM2_ALG_CBC,
    TPM2_ALG_CFB,
    TPM2_ALG_ECB,
    TPM2_ALG_FIRST,/// Not currently in use
    TPM2_ALG_LAST,/// Not currently in use
}

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

#[derive(Copy, Clone, Debug)]
pub enum ObjectType {
    NULL,
    RSA,/// Assymetric
    ECC,/// Assymetric
    KEYEDHASH,/// Symmetric
    SYMCIPHER,/// Symmetric
}

impl ObjectType {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// key type.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            ObjectType::NULL => TPM2_ALG_NULL,
            ObjectType::RSA => TPM2_ALG_RSA,
            ObjectType::ECC => TPM2_ALG_ECC,
            ObjectType::KEYEDHASH => TPM2_ALG_KEYEDHASH,
            ObjectType::SYMCIPHER => TPM2_ALG_SYMCIPHER,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for ObjectType {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_NULL => Ok(ObjectType::NULL),
            TPM2_ALG_RSA => Ok(ObjectType::RSA),
            TPM2_ALG_ECC => Ok(ObjectType::ECC),
            TPM2_ALG_KEYEDHASH => Ok(ObjectType::KEYEDHASH),
            TPM2_ALG_SYMCIPHER => Ok(ObjectType::SYMCIPHER),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
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
#[derive(Copy, Clone, Debug)]
pub enum AsymmetricAlgorithm {
    RSA,
    ECC
}

impl AsymmetricAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// asymmetric algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AsymmetricAlgorithm::RSA => TPM2_ALG_RSA,
            AsymmetricAlgorithm::ECC => TPM2_ALG_ECC,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AsymmetricAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSA => Ok(AsymmetricAlgorithm::RSA),
            TPM2_ALG_ECC => Ok(AsymmetricAlgorithm::ECC),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Keyed hash (KEYEDHASH)
///
////////////////////////////////////////////////

/// Enum containing keyed hash
#[derive(Copy, Clone, Debug)]
pub enum KeyedHash {
    HMAC,
    XOR,
    CMAC,
}

impl KeyedHash {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// keyed hash.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            KeyedHash::HMAC => TPM2_ALG_HMAC,
            KeyedHash::XOR => TPM2_ALG_XOR,
            KeyedHash::CMAC => TPM2_ALG_CMAC,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for KeyedHash {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_HMAC => Ok(KeyedHash::HMAC),
            TPM2_ALG_XOR => Ok(KeyedHash::XOR),
            TPM2_ALG_CMAC => Ok(KeyedHash::CMAC),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Symmetric algorithms.(SYMCIPHER)
///
////////////////////////////////////////////////

/// Enum containing symmetric algorithms.
#[derive(Copy, Clone, Debug)]
pub enum SymmetricAlgorithm {
    AES,
    CAMELLIA,
    SM4,
    ///TDES, it has been banned.
}

impl SymmetricAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// symmetric algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            SymmetricAlgorithm::AES => TPM2_ALG_AES,
            SymmetricAlgorithm::CAMELLIA => TPM2_ALG_CAMELLIA,
            SymmetricAlgorithm::SM4 => TPM2_ALG_SM4,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for SymmetricAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_AES => Ok(SymmetricAlgorithm::AES),
            TPM2_ALG_CAMELLIA => Ok(SymmetricAlgorithm::CAMELLIA),
            TPM2_ALG_SM4 => Ok(SymmetricAlgorithm::SM4),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Hashing Algorithms
///
////////////////////////////////////////////////

/// Enum containing the supported hash algorithms
#[derive(Copy, Clone, Debug)]
pub enum HashingAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SM3_256,
    SHA3_256,
    SHA3_384,
    SHA3_512,
}

impl HashingAlgorithm {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// hash algorithm.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            HashingAlgorithm::SHA1 => TPM2_ALG_SHA1,
            HashingAlgorithm::SHA256 => TPM2_ALG_SHA256,
            HashingAlgorithm::SHA384 => TPM2_ALG_SHA384,
            HashingAlgorithm::SHA512 => TPM2_ALG_SHA512,
            HashingAlgorithm::SM3_256 => TPM2_ALG_SM3_256,
            HashingAlgorithm::SHA3_256 => TPM2_ALG_SHA3_256,
            HashingAlgorithm::SHA3_384 => TPM2_ALG_SHA3_384,
            HashingAlgorithm::SHA3_512 => TPM2_ALG_SHA3_512,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for HashingAlgorithm {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_SHA1 => Ok(HashingAlgorithm::SHA1),
            TPM2_ALG_SHA256 => Ok(HashingAlgorithm::SHA256),
            TPM2_ALG_SHA384 => Ok(HashingAlgorithm::SHA384),
            TPM2_ALG_SHA512 => Ok(HashingAlgorithm::SHA512),
            TPM2_ALG_SM3_256 => Ok(HashingAlgorithm::SM3_256),
            TPM2_ALG_SHA3_256 => Ok(HashingAlgorithm::SHA3_256),
            TPM2_ALG_SHA3_384 => Ok(HashingAlgorithm::SHA3_384),
            TPM2_ALG_SHA3_512 => Ok(HashingAlgorithm::SHA3_512),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing signature schemes
#[derive(Copy, Clone, Debug)]
pub enum SignatureScheme {
    RSASSA,
    RSAPSS,
    ECDSA,
    ECDAA,
    ECSCHNORR,
    SM2,
}

impl SignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// signature scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            SignatureScheme::RSASSA => TPM2_ALG_RSASSA,
            SignatureScheme::RSAPSS => TPM2_ALG_RSAPSS,
            SignatureScheme::ECDSA => TPM2_ALG_ECDSA,
            SignatureScheme::ECDAA => TPM2_ALG_ECDAA,
            SignatureScheme::ECSCHNORR => TPM2_ALG_ECSCHNORR,
            SignatureScheme::SM2 => TPM2_ALG_SM2,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for SignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSASSA => Ok(SignatureScheme::RSASSA),
            TPM2_ALG_RSAPSS => Ok(SignatureScheme::RSAPSS),
            TPM2_ALG_ECDSA => Ok(SignatureScheme::ECDSA),
            TPM2_ALG_ECDAA => Ok(SignatureScheme::ECDAA),
            TPM2_ALG_ECSCHNORR => Ok(SignatureScheme::ECSCHNORR),
            TPM2_ALG_SM2 => Ok(SignatureScheme::SM2),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// RSA Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing RSA signature schemes
#[derive(Copy, Clone, Debug)]
pub enum RsaSignatureScheme {
    RSASSA,
    RSAPSS,
}

impl RsaSignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// RSA signature scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            RsaSignatureScheme::RSASSA => TPM2_ALG_RSASSA,
            RsaSignatureScheme::RSAPSS => TPM2_ALG_RSAPSS,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for RsaSignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_RSASSA => Ok(RsaSignatureScheme::RSASSA),
            TPM2_ALG_RSAPSS => Ok(RsaSignatureScheme::RSAPSS),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// ECC Signature Schemes
///
////////////////////////////////////////////////

/// Enum containing ECC signature schemes
#[derive(Copy, Clone, Debug)]
pub enum EccSignatureScheme {
    ECDSA,
    ECDAA,
    ECSCHNORR,
    SM2,
}

impl EccSignatureScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// signing scheme
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            EccSignatureScheme::ECDSA => TPM2_ALG_ECDSA,
            EccSignatureScheme::ECDAA => TPM2_ALG_ECDAA,
            EccSignatureScheme::ECSCHNORR => TPM2_ALG_ECSCHNORR,
            EccSignatureScheme::SM2 => TPM2_ALG_SM2,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for EccSignatureScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_ECDSA => Ok(EccSignatureScheme::ECDSA),
            TPM2_ALG_ECDAA => Ok(EccSignatureScheme::ECDAA),
            TPM2_ALG_ECSCHNORR => Ok(EccSignatureScheme::ECSCHNORR),
            TPM2_ALG_SM2 => Ok(EccSignatureScheme::SM2),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Asymmetric Encryption Schemes
///
////////////////////////////////////////////////

// Enum containing asymmetric encryption schemes
#[derive(Copy, Clone, Debug)]
pub enum AsymmetricEncryptionScheme {
    OAEP,
    RSAES,
    ECDH,
}

impl AsymmetricEncryptionScheme {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// asymmetric encryption scheme.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AsymmetricEncryptionScheme::OAEP => TPM2_ALG_OAEP,
            AsymmetricEncryptionScheme::RSAES => TPM2_ALG_RSAES,
            AsymmetricEncryptionScheme::ECDH => TPM2_ALG_ECDH,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AsymmetricEncryptionScheme {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_OAEP => Ok(AsymmetricEncryptionScheme::OAEP),
            TPM2_ALG_RSAES => Ok(AsymmetricEncryptionScheme::RSAES),
            TPM2_ALG_ECDH => Ok(AsymmetricEncryptionScheme::ECDH),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Encryption Modes
///
////////////////////////////////////////////////

// Enum containing encryption modes
#[derive(Copy, Clone, Debug)]
pub enum EncryptionMode {
    CTR,
    OFB,
    CBC,
    CFB,
    ECB
}

impl EncryptionMode {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// encryption mode.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            EncryptionMode::CTR => TPM2_ALG_CTR,
            EncryptionMode::OFB => TPM2_ALG_OFB,
            EncryptionMode::CBC => TPM2_ALG_CBC,
            EncryptionMode::CFB => TPM2_ALG_CFB,
            EncryptionMode::ECB => TPM2_ALG_ECB,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for EncryptionMode {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_CTR => Ok(EncryptionMode::CTR),
            TPM2_ALG_OFB => Ok(EncryptionMode::OFB),
            TPM2_ALG_CBC => Ok(EncryptionMode::CBC),
            TPM2_ALG_CFB => Ok(EncryptionMode::CFB),
            TPM2_ALG_ECB => Ok(EncryptionMode::ECB),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Mask Generation Functions
///
////////////////////////////////////////////////

// Enum containing mask generation functions.
#[derive(Copy, Clone, Debug)]
pub enum MaskGenerationFunction {
    MGF1,
}

impl MaskGenerationFunction {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// mask generation function.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            MaskGenerationFunction::MGF1 => TPM2_ALG_MGF1,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for MaskGenerationFunction {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_MGF1 => Ok(MaskGenerationFunction::MGF1),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}
////////////////////////////////////////////////
///
/// Key Derivation Functions
///
////////////////////////////////////////////////

// Enum containing key derivation functions.
#[derive(Copy, Clone, Debug)]
pub enum KeyDerivationFunction {
    KDF1_SP800_56A,
    KDF2,
    KDF1_SP800_108,
    ECMQV,
}

impl KeyDerivationFunction {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// key derivation function.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            KeyDerivationFunction::KDF1_SP800_56A => TPM2_ALG_KDF1_SP800_56A,
            KeyDerivationFunction::KDF2 => TPM2_ALG_KDF2,
            KeyDerivationFunction::KDF1_SP800_108 => TPM2_ALG_KDF1_SP800_108,
            KeyDerivationFunction::ECMQV => TPM2_ALG_ECMQV,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_KDF1_SP800_56A => Ok(KeyDerivationFunction::KDF1_SP800_56A),
            TPM2_ALG_KDF2 => Ok(KeyDerivationFunction::KDF2),
            TPM2_ALG_KDF1_SP800_108 => Ok(KeyDerivationFunction::KDF1_SP800_108),
            TPM2_ALG_ECMQV => Ok(KeyDerivationFunction::ECMQV),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

////////////////////////////////////////////////
///
/// Algorithmic Error
///
////////////////////////////////////////////////

/// Enum continaing algorithmic errors.
#[derive(Copy, Clone, Debug)]
pub enum AlgorithmicError {
    ERROR,
}

impl AlgorithmicError {
    /// Returns the TPM2_ALG_ID that corresponds to the
    /// algorithmic error.
    pub fn alg_id(self) -> TPM2_ALG_ID {
        match self {
            AlgorithmicError::ERROR => TPM2_ALG_ERROR,
        }
    }
}

impl TryFrom<TPM2_ALG_ID> for AlgorithmicError {
    type Error = Error;

    fn try_from(algorithm_id: TPM2_ALG_ID) -> Result<Self> {
        match algorithm_id {
            TPM2_ALG_ERROR => Ok(AlgorithmicError::ERROR),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}
