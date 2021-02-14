// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::Algorithm,
    tss2_esys::{
        TPMI_ALG_ASYM, TPMI_ALG_HASH, TPMI_ALG_KDF, TPMI_ALG_KEYEDHASH_SCHEME, TPMI_ALG_SIG_SCHEME,
        TPMI_ALG_SYM, TPMI_ALG_SYM_MODE, TPMI_ALG_SYM_OBJECT,
    },
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// Enum containing the supported hash algorithms
///
/// # Details
/// This corresponds to TPMI_ALG_HASH interface type.
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
    Null,
}

impl From<HashingAlgorithm> for Algorithm {
    fn from(hashing_algorithm: HashingAlgorithm) -> Self {
        match hashing_algorithm {
            HashingAlgorithm::Sha1 => Algorithm::Sha1,
            HashingAlgorithm::Sha256 => Algorithm::Sha256,
            HashingAlgorithm::Sha384 => Algorithm::Sha384,
            HashingAlgorithm::Sha512 => Algorithm::Sha512,
            HashingAlgorithm::Sm3_256 => Algorithm::Sm3_256,
            HashingAlgorithm::Sha3_256 => Algorithm::Sha3_256,
            HashingAlgorithm::Sha3_384 => Algorithm::Sha3_384,
            HashingAlgorithm::Sha3_512 => Algorithm::Sha3_512,
            HashingAlgorithm::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for HashingAlgorithm {
    type Error = Error;

    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Sha1 => Ok(HashingAlgorithm::Sha1),
            Algorithm::Sha256 => Ok(HashingAlgorithm::Sha256),
            Algorithm::Sha384 => Ok(HashingAlgorithm::Sha384),
            Algorithm::Sha512 => Ok(HashingAlgorithm::Sha512),
            Algorithm::Sm3_256 => Ok(HashingAlgorithm::Sm3_256),
            Algorithm::Sha3_256 => Ok(HashingAlgorithm::Sha3_256),
            Algorithm::Sha3_384 => Ok(HashingAlgorithm::Sha3_384),
            Algorithm::Sha3_512 => Ok(HashingAlgorithm::Sha3_512),
            Algorithm::Null => Ok(HashingAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<HashingAlgorithm> for TPMI_ALG_HASH {
    fn from(hashing_algorithm: HashingAlgorithm) -> Self {
        Algorithm::from(hashing_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_HASH> for HashingAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_hash: TPMI_ALG_HASH) -> Result<Self> {
        HashingAlgorithm::try_from(Algorithm::try_from(tpmi_alg_hash)?)
    }
}

/// Enum containing the supported keyed hash scheme
///
/// # Details
/// This corresponds to TPMI_ALG_KEYEDHASH_SCHEME interface type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyedHashSchemeAlgorithm {
    Hmac,
    Xor,
    Null,
}

impl From<KeyedHashSchemeAlgorithm> for Algorithm {
    fn from(keyed_hash_scheme: KeyedHashSchemeAlgorithm) -> Self {
        match keyed_hash_scheme {
            KeyedHashSchemeAlgorithm::Hmac => Algorithm::Hmac,
            KeyedHashSchemeAlgorithm::Xor => Algorithm::Xor,
            KeyedHashSchemeAlgorithm::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for KeyedHashSchemeAlgorithm {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Hmac => Ok(KeyedHashSchemeAlgorithm::Hmac),
            Algorithm::Xor => Ok(KeyedHashSchemeAlgorithm::Xor),
            Algorithm::Null => Ok(KeyedHashSchemeAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<KeyedHashSchemeAlgorithm> for TPMI_ALG_KEYEDHASH_SCHEME {
    fn from(keyed_hash_scheme: KeyedHashSchemeAlgorithm) -> Self {
        Algorithm::from(keyed_hash_scheme).into()
    }
}

impl TryFrom<TPMI_ALG_KEYEDHASH_SCHEME> for KeyedHashSchemeAlgorithm {
    type Error = Error;
    fn try_from(tpmi_alg_keyed_hash_scheme: TPMI_ALG_KEYEDHASH_SCHEME) -> Result<Self> {
        KeyedHashSchemeAlgorithm::try_from(Algorithm::try_from(tpmi_alg_keyed_hash_scheme)?)
    }
}

/// Enum containing key derivation functions interface type.
///
/// # Details this corresponds to the TPMI_ALG_KDF
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyDerivationFunction {
    Kdf1Sp800_56a,
    Kdf2,
    Kdf1Sp800_108,
    EcMqv,
}

impl From<KeyDerivationFunction> for Algorithm {
    fn from(key_derivation_function: KeyDerivationFunction) -> Self {
        match key_derivation_function {
            KeyDerivationFunction::Kdf1Sp800_56a => Algorithm::Kdf1Sp800_56a,
            KeyDerivationFunction::Kdf2 => Algorithm::Kdf2,
            KeyDerivationFunction::Kdf1Sp800_108 => Algorithm::Kdf1Sp800_108,
            KeyDerivationFunction::EcMqv => Algorithm::EcMqv,
        }
    }
}

impl TryFrom<Algorithm> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(algorithm_id: Algorithm) -> Result<Self> {
        match algorithm_id {
            Algorithm::Kdf1Sp800_56a => Ok(KeyDerivationFunction::Kdf1Sp800_56a),
            Algorithm::Kdf2 => Ok(KeyDerivationFunction::Kdf2),
            Algorithm::Kdf1Sp800_108 => Ok(KeyDerivationFunction::Kdf1Sp800_108),
            Algorithm::EcMqv => Ok(KeyDerivationFunction::EcMqv),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<KeyDerivationFunction> for TPMI_ALG_KDF {
    fn from(key_derivation_function: KeyDerivationFunction) -> Self {
        Algorithm::from(key_derivation_function).into()
    }
}

impl TryFrom<TPMI_ALG_KDF> for KeyDerivationFunction {
    type Error = Error;

    fn try_from(tpmi_alg_kdf: TPMI_ALG_KDF) -> Result<Self> {
        KeyDerivationFunction::try_from(Algorithm::try_from(tpmi_alg_kdf)?)
    }
}

/// Enum representing the symmetric algorithm interface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SYM.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricAlgorithm {
    Tdes,
    Aes,
    Sm4,
    Camellia,
    Xor,
    Null,
}

impl From<SymmetricAlgorithm> for Algorithm {
    fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
        match symmetric_algorithm {
            SymmetricAlgorithm::Tdes => Algorithm::Tdes,
            SymmetricAlgorithm::Aes => Algorithm::Aes,
            SymmetricAlgorithm::Sm4 => Algorithm::Sm4,
            SymmetricAlgorithm::Camellia => Algorithm::Camellia,
            SymmetricAlgorithm::Xor => Algorithm::Xor,
            SymmetricAlgorithm::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for SymmetricAlgorithm {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Tdes => Ok(SymmetricAlgorithm::Tdes),
            Algorithm::Aes => Ok(SymmetricAlgorithm::Aes),
            Algorithm::Sm4 => Ok(SymmetricAlgorithm::Sm4),
            Algorithm::Camellia => Ok(SymmetricAlgorithm::Camellia),
            Algorithm::Xor => Ok(SymmetricAlgorithm::Xor),
            Algorithm::Null => Ok(SymmetricAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricAlgorithm> for TPMI_ALG_SYM {
    fn from(symmetric_algorithm: SymmetricAlgorithm) -> Self {
        Algorithm::from(symmetric_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_SYM> for SymmetricAlgorithm {
    type Error = Error;

    fn try_from(tpmi_alg_sym: TPMI_ALG_SYM) -> Result<Self> {
        SymmetricAlgorithm::try_from(Algorithm::try_from(tpmi_alg_sym)?)
    }
}

/// Enum representing the symmetric mode interface type.
///
/// # Details
/// Corresponds to TPMI_ALG_SYM_MODE.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricMode {
    Ctr,
    Ofb,
    Cfb,
    Ecb,
    Null,
}

impl From<SymmetricMode> for Algorithm {
    fn from(symmetric_mode: SymmetricMode) -> Self {
        match symmetric_mode {
            SymmetricMode::Ctr => Algorithm::Ctr,
            SymmetricMode::Ofb => Algorithm::Ofb,
            SymmetricMode::Cfb => Algorithm::Cfb,
            SymmetricMode::Ecb => Algorithm::Ecb,
            SymmetricMode::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for SymmetricMode {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<SymmetricMode> {
        match algorithm {
            Algorithm::Ctr => Ok(SymmetricMode::Ctr),
            Algorithm::Ofb => Ok(SymmetricMode::Ofb),
            Algorithm::Cfb => Ok(SymmetricMode::Cfb),
            Algorithm::Ecb => Ok(SymmetricMode::Ecb),
            Algorithm::Null => Ok(SymmetricMode::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricMode> for TPMI_ALG_SYM_MODE {
    fn from(symmetric_mode: SymmetricMode) -> Self {
        Algorithm::from(symmetric_mode).into()
    }
}

impl TryFrom<TPMI_ALG_SYM_MODE> for SymmetricMode {
    type Error = Error;

    fn try_from(tpmi_alg_sym_mode: TPMI_ALG_SYM_MODE) -> Result<Self> {
        SymmetricMode::try_from(Algorithm::try_from(tpmi_alg_sym_mode)?)
    }
}

/// Enum representing the asymmetric algorithm interface type.
///
/// # Details
/// This corresponds to TPMI_ALG_ASYM
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AsymmetricAlgorithm {
    Rsa,
    Ecc,
    Null,
}

impl From<AsymmetricAlgorithm> for Algorithm {
    fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
        match asymmetric_algorithm {
            AsymmetricAlgorithm::Rsa => Algorithm::Rsa,
            AsymmetricAlgorithm::Ecc => Algorithm::Ecc,
            AsymmetricAlgorithm::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Rsa => Ok(AsymmetricAlgorithm::Rsa),
            Algorithm::Ecc => Ok(AsymmetricAlgorithm::Ecc),
            Algorithm::Null => Ok(AsymmetricAlgorithm::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<AsymmetricAlgorithm> for TPMI_ALG_ASYM {
    fn from(asymmetric_algorithm: AsymmetricAlgorithm) -> Self {
        Algorithm::from(asymmetric_algorithm).into()
    }
}

impl TryFrom<TPMI_ALG_ASYM> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(tpmi_alg_sym: TPMI_ALG_ASYM) -> Result<Self> {
        AsymmetricAlgorithm::try_from(Algorithm::try_from(tpmi_alg_sym)?)
    }
}

/// Enum representing the signature scheme interface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SIG_SCHEME
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SignatureScheme {
    RsaSsa,
    RsaPss,
    EcDsa,
    EcDaa,
    Sm2,
    EcSchnorr,
    Hmac,
    Null,
}

impl From<SignatureScheme> for Algorithm {
    fn from(signature_scheme: SignatureScheme) -> Self {
        match signature_scheme {
            SignatureScheme::RsaSsa => Algorithm::RsaSsa,
            SignatureScheme::RsaPss => Algorithm::RsaPss,
            SignatureScheme::EcDsa => Algorithm::EcDsa,
            SignatureScheme::EcDaa => Algorithm::EcDaa,
            SignatureScheme::Sm2 => Algorithm::Sm2,
            SignatureScheme::EcSchnorr => Algorithm::EcSchnorr,
            SignatureScheme::Hmac => Algorithm::Hmac,
            SignatureScheme::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for SignatureScheme {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::RsaSsa => Ok(SignatureScheme::RsaSsa),
            Algorithm::RsaPss => Ok(SignatureScheme::RsaPss),
            Algorithm::EcDsa => Ok(SignatureScheme::EcDsa),
            Algorithm::EcDaa => Ok(SignatureScheme::EcDaa),
            Algorithm::Sm2 => Ok(SignatureScheme::Sm2),
            Algorithm::EcSchnorr => Ok(SignatureScheme::EcSchnorr),
            Algorithm::Hmac => Ok(SignatureScheme::Hmac),
            Algorithm::Null => Ok(SignatureScheme::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SignatureScheme> for TPMI_ALG_SIG_SCHEME {
    fn from(signature_scheme: SignatureScheme) -> Self {
        Algorithm::from(signature_scheme).into()
    }
}

impl TryFrom<TPMI_ALG_SIG_SCHEME> for SignatureScheme {
    type Error = Error;
    fn try_from(tpmi_alg_sym_scheme: TPMI_ALG_SIG_SCHEME) -> Result<Self> {
        SignatureScheme::try_from(Algorithm::try_from(tpmi_alg_sym_scheme)?)
    }
}

// A convinience conversion into AsymmetricAlgorithm
// that is associated with the signature scheme.
impl TryFrom<SignatureScheme> for AsymmetricAlgorithm {
    type Error = Error;
    fn try_from(signature_scheme: SignatureScheme) -> Result<Self> {
        match signature_scheme {
            SignatureScheme::RsaSsa => Ok(AsymmetricAlgorithm::Rsa),
            SignatureScheme::RsaPss => Ok(AsymmetricAlgorithm::Rsa),
            SignatureScheme::EcDsa => Ok(AsymmetricAlgorithm::Ecc),
            SignatureScheme::EcDaa => Ok(AsymmetricAlgorithm::Ecc),
            SignatureScheme::Sm2 => Ok(AsymmetricAlgorithm::Ecc),
            SignatureScheme::EcSchnorr => Ok(AsymmetricAlgorithm::Ecc),
            _ => {
                // HMAC is for symmetric algorithms
                //
                // Null could be converted into AsymmetricAlgorithm::Null
                // but I do not know if that is usefull.
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

/// Enum repsenting the symmetric object inetrface type.
///
/// # Details
/// This corresponds to TPMI_ALG_SYM_OBJECT
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SymmetricObject {
    Tdes,
    Aes,
    Sm4,
    Camellia,
    Null,
}

impl From<SymmetricObject> for Algorithm {
    fn from(symmetric_object: SymmetricObject) -> Self {
        match symmetric_object {
            SymmetricObject::Tdes => Algorithm::Tdes,
            SymmetricObject::Aes => Algorithm::Aes,
            SymmetricObject::Sm4 => Algorithm::Sm4,
            SymmetricObject::Camellia => Algorithm::Camellia,
            SymmetricObject::Null => Algorithm::Null,
        }
    }
}

impl TryFrom<Algorithm> for SymmetricObject {
    type Error = Error;
    fn try_from(algorithm: Algorithm) -> Result<Self> {
        match algorithm {
            Algorithm::Tdes => Ok(SymmetricObject::Tdes),
            Algorithm::Aes => Ok(SymmetricObject::Aes),
            Algorithm::Sm4 => Ok(SymmetricObject::Sm4),
            Algorithm::Camellia => Ok(SymmetricObject::Camellia),
            Algorithm::Null => Ok(SymmetricObject::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<SymmetricObject> for TPMI_ALG_SYM_OBJECT {
    fn from(symmetric_object: SymmetricObject) -> Self {
        Algorithm::from(symmetric_object).into()
    }
}

impl TryFrom<TPMI_ALG_SYM_OBJECT> for SymmetricObject {
    type Error = Error;

    fn try_from(tpmi_alg_sym_object: TPMI_ALG_SYM_OBJECT) -> Result<Self> {
        SymmetricObject::try_from(Algorithm::try_from(tpmi_alg_sym_object)?)
    }
}
