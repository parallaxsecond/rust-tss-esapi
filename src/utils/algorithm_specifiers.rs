// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::constants::{
    TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_CBC, TPM2_ALG_CFB, TPM2_ALG_CTR, TPM2_ALG_ECB,
    TPM2_ALG_ECC, TPM2_ALG_ECDAA, TPM2_ALG_ECDH, TPM2_ALG_ECDSA, TPM2_ALG_ECMQV,
    TPM2_ALG_ECSCHNORR, TPM2_ALG_ERROR, TPM2_ALG_HMAC, TPM2_ALG_KDF1_SP800_108,
    TPM2_ALG_KDF1_SP800_56A, TPM2_ALG_KDF2, TPM2_ALG_KEYEDHASH, TPM2_ALG_MGF1, TPM2_ALG_NULL,
    TPM2_ALG_OAEP, TPM2_ALG_OFB, TPM2_ALG_RSA, TPM2_ALG_RSAES, TPM2_ALG_RSAPSS, TPM2_ALG_RSASSA,
    TPM2_ALG_SHA1, TPM2_ALG_SHA256, TPM2_ALG_SHA384, TPM2_ALG_SHA3_256, TPM2_ALG_SHA3_384,
    TPM2_ALG_SHA3_512, TPM2_ALG_SHA512, TPM2_ALG_SM2, TPM2_ALG_SM3_256, TPM2_ALG_SM4,
    TPM2_ALG_SYMCIPHER, TPM2_ALG_TDES, TPM2_ALG_XOR, TPM2_ECC_BN_P256, TPM2_ECC_BN_P638,
    TPM2_ECC_NIST_P192, TPM2_ECC_NIST_P224, TPM2_ECC_NIST_P256, TPM2_ECC_NIST_P384,
    TPM2_ECC_NIST_P521, TPM2_ECC_SM2_P256,
};

use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::{
    TPM2_ALG_ID, TPMI_ECC_CURVE, TPMS_SYMCIPHER_PARMS, TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT,
};
use crate::utils::TpmtSymDefBuilder;
use std::convert::{From, TryFrom};

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

impl From<ObjectType> for TPM2_ALG_ID {
    fn from(object_type: ObjectType) -> Self {
        match object_type {
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

impl From<AsymmetricAlgorithm> for TPM2_ALG_ID {
    fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
        match asymmetric_algorithm {
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

impl From<KeyedHash> for TPM2_ALG_ID {
    fn from(keyed_hash: KeyedHash) -> Self {
        match keyed_hash {
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
    Tdes,
    Xor,
}

impl From<SymmetricAlgorithm> for TPM2_ALG_ID {
    fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
        match symmetric_algorithm {
            SymmetricAlgorithm::Aes => TPM2_ALG_AES,
            SymmetricAlgorithm::Camellia => TPM2_ALG_CAMELLIA,
            SymmetricAlgorithm::Sm4 => TPM2_ALG_SM4,
            SymmetricAlgorithm::Tdes => TPM2_ALG_TDES,
            SymmetricAlgorithm::Xor => TPM2_ALG_XOR,
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
            TPM2_ALG_TDES => Ok(SymmetricAlgorithm::Tdes),
            TPM2_ALG_XOR => Ok(SymmetricAlgorithm::Xor),
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
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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

impl From<HashingAlgorithm> for TPM2_ALG_ID {
    fn from(hashing_algorithm: HashingAlgorithm) -> Self {
        match hashing_algorithm {
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

impl From<SignatureScheme> for TPM2_ALG_ID {
    fn from(signature_scheme: SignatureScheme) -> Self {
        match signature_scheme {
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

impl From<RsaSignatureScheme> for TPM2_ALG_ID {
    fn from(rsa_signature_scheme: RsaSignatureScheme) -> Self {
        match rsa_signature_scheme {
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

impl From<EccSignatureScheme> for TPM2_ALG_ID {
    fn from(ecc_signature_scheme: EccSignatureScheme) -> Self {
        match ecc_signature_scheme {
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

impl From<AsymmetricEncryptionScheme> for TPM2_ALG_ID {
    fn from(asymmetric_encryption_scheme: AsymmetricEncryptionScheme) -> Self {
        match asymmetric_encryption_scheme {
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

impl From<EncryptionMode> for TPM2_ALG_ID {
    fn from(encryption_mode: EncryptionMode) -> Self {
        match encryption_mode {
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

impl From<MaskGenerationFunction> for TPM2_ALG_ID {
    fn from(mask_generation_function: MaskGenerationFunction) -> Self {
        match mask_generation_function {
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

impl From<KeyDerivationFunction> for TPM2_ALG_ID {
    fn from(key_derivation_function: KeyDerivationFunction) -> Self {
        match key_derivation_function {
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

impl From<AlgorithmicError> for TPM2_ALG_ID {
    fn from(algorithmic_error: AlgorithmicError) -> Self {
        match algorithmic_error {
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

/// Block cipher identifiers
///
/// Structure useful for handling an abstract representation of ciphers. Ciphers are
/// defined foremost through their symmetric algorithm and, depending on the type of that
/// algorithm, on a set of other values.
#[derive(Copy, Clone, Debug)]
pub struct Cipher {
    algorithm: SymmetricAlgorithm,
    mode: Option<EncryptionMode>,
    key_bits: Option<u16>,
    hash: Option<HashingAlgorithm>,
}

impl Cipher {
    /// Constructor for AES cipher identifier
    ///
    /// `key_bits` must be one of 128, 192 or 256.
    pub fn aes(mode: EncryptionMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            128 | 192 | 256 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for Camellia cipher identifier
    ///
    /// `key_bits` must be one of 128, 192 or 256.
    pub fn camellia(mode: EncryptionMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            128 | 192 | 256 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Camellia,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for Triple DES cipher identifier
    ///
    /// `key_bits` must be one of 56, 112 or 168.
    pub fn tdes(mode: EncryptionMode, key_bits: u16) -> Result<Self> {
        match key_bits {
            56 | 112 | 168 => (),
            _ => return Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }

        Ok(Cipher {
            algorithm: SymmetricAlgorithm::Tdes,
            mode: Some(mode),
            key_bits: Some(key_bits),
            hash: None,
        })
    }

    /// Constructor for SM4 cipher identifier
    pub fn sm4(mode: EncryptionMode) -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Sm4,
            mode: Some(mode),
            key_bits: Some(128),
            hash: None,
        }
    }

    /// Constructor for XOR "cipher" identifier
    pub fn xor(hash: HashingAlgorithm) -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Xor,
            mode: None,
            key_bits: None,
            hash: Some(hash),
        }
    }

    /// Get general object type for symmetric ciphers.
    pub fn object_type() -> TPM2_ALG_ID {
        TPM2_ALG_SYMCIPHER
    }

    /// Get the cipher key length.
    pub fn key_bits(self) -> Option<u16> {
        self.key_bits
    }

    /// Get the cipher mode.
    pub fn mode(self) -> Option<EncryptionMode> {
        self.mode
    }

    /// Get the hash algorithm used with an XOR cipher
    pub fn hash(self) -> Option<HashingAlgorithm> {
        self.hash
    }

    /// Get the TSS algorithm ID.
    pub fn algorithm_id(self) -> TPM2_ALG_ID {
        self.algorithm.into()
    }

    /// Constructor for 128 bit AES in CFB mode.
    pub fn aes_128_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(EncryptionMode::Cfb),
            key_bits: Some(128),
            hash: None,
        }
    }

    /// Constructor for 256 bit AES in CFB mode.
    pub fn aes_256_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(EncryptionMode::Cfb),
            key_bits: Some(256),
            hash: None,
        }
    }
}

impl From<Cipher> for TPMT_SYM_DEF {
    fn from(cipher: Cipher) -> Self {
        let key_bits = if let Some(bits) = cipher.key_bits {
            bits
        } else if let Some(hash) = cipher.hash {
            hash.into()
        } else {
            TPM2_ALG_NULL
        };

        let mode = if let Some(mode) = cipher.mode {
            mode.into()
        } else {
            TPM2_ALG_NULL
        };

        TpmtSymDefBuilder::new()
            .with_algorithm(cipher.algorithm_id())
            .with_key_bits(key_bits)
            .with_mode(mode)
            .build()
            .unwrap() // all params are strictly controlled, should not fail
    }
}

impl From<Cipher> for TPMT_SYM_DEF_OBJECT {
    fn from(cipher: Cipher) -> Self {
        let key_bits = if let Some(bits) = cipher.key_bits {
            bits
        } else if let Some(hash) = cipher.hash {
            hash.into()
        } else {
            TPM2_ALG_NULL
        };

        let mode = if let Some(mode) = cipher.mode {
            mode.into()
        } else {
            TPM2_ALG_NULL
        };

        TpmtSymDefBuilder::new()
            .with_algorithm(cipher.algorithm_id())
            .with_key_bits(key_bits)
            .with_mode(mode)
            .build_object()
            .unwrap() // all params are strictly controlled, should not fail
    }
}

impl From<Cipher> for TPMS_SYMCIPHER_PARMS {
    fn from(cipher: Cipher) -> Self {
        TPMS_SYMCIPHER_PARMS { sym: cipher.into() }
    }
}

/// Identifiers for elliptic curves supported by TPMs.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum EllipticCurve {
    NistP192,
    NistP224,
    NistP256,
    NistP384,
    NistP521,
    BnP256,
    BnP638,
    Sm2P256,
}

impl From<EllipticCurve> for TPMI_ECC_CURVE {
    fn from(curve: EllipticCurve) -> Self {
        match curve {
            EllipticCurve::NistP192 => TPM2_ECC_NIST_P192,
            EllipticCurve::NistP224 => TPM2_ECC_NIST_P224,
            EllipticCurve::NistP256 => TPM2_ECC_NIST_P256,
            EllipticCurve::NistP384 => TPM2_ECC_NIST_P384,
            EllipticCurve::NistP521 => TPM2_ECC_NIST_P521,
            EllipticCurve::BnP256 => TPM2_ECC_BN_P256,
            EllipticCurve::BnP638 => TPM2_ECC_BN_P638,
            EllipticCurve::Sm2P256 => TPM2_ECC_SM2_P256,
        }
    }
}

impl TryFrom<TPMI_ECC_CURVE> for EllipticCurve {
    type Error = Error;

    fn try_from(curve: TPMI_ECC_CURVE) -> Result<Self> {
        match curve {
            TPM2_ECC_NIST_P192 => Ok(EllipticCurve::NistP192),
            TPM2_ECC_NIST_P224 => Ok(EllipticCurve::NistP224),
            TPM2_ECC_NIST_P256 => Ok(EllipticCurve::NistP256),
            TPM2_ECC_NIST_P384 => Ok(EllipticCurve::NistP384),
            TPM2_ECC_NIST_P521 => Ok(EllipticCurve::NistP521),
            TPM2_ECC_BN_P256 => Ok(EllipticCurve::BnP256),
            TPM2_ECC_BN_P638 => Ok(EllipticCurve::BnP638),
            TPM2_ECC_SM2_P256 => Ok(EllipticCurve::Sm2P256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
