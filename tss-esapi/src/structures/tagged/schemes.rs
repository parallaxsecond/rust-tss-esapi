// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::{
        EccSchemeAlgorithm, HashingAlgorithm, KeyDerivationFunction, KeyedHashSchemeAlgorithm,
        RsaDecryptAlgorithm, RsaSchemeAlgorithm, SignatureSchemeAlgorithm,
    },
    structures::schemes::{EcDaaScheme, HashScheme, HmacScheme, XorScheme},
    tss2_esys::{
        TPMT_ECC_SCHEME, TPMT_KDF_SCHEME, TPMT_KEYEDHASH_SCHEME, TPMT_RSA_DECRYPT, TPMT_RSA_SCHEME,
        TPMT_SIG_SCHEME, TPMU_ASYM_SCHEME, TPMU_KDF_SCHEME, TPMU_SCHEME_KEYEDHASH, TPMU_SIG_SCHEME,
    },
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Enum representing the keyed hash scheme.
///
/// # Details
/// This corresponds to TPMT_SCHEME_KEYEDHASH.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyedHashScheme {
    Xor { xor_scheme: XorScheme },
    Hmac { hmac_scheme: HmacScheme },
    Null,
}

impl KeyedHashScheme {
    pub const HMAC_SHA_256: KeyedHashScheme = KeyedHashScheme::Hmac {
        hmac_scheme: HmacScheme::new(HashingAlgorithm::Sha256),
    };
}

impl From<KeyedHashScheme> for TPMT_KEYEDHASH_SCHEME {
    fn from(keyed_hash_scheme: KeyedHashScheme) -> Self {
        match keyed_hash_scheme {
            KeyedHashScheme::Xor { xor_scheme } => TPMT_KEYEDHASH_SCHEME {
                scheme: KeyedHashSchemeAlgorithm::Xor.into(),
                details: TPMU_SCHEME_KEYEDHASH {
                    exclusiveOr: xor_scheme.into(),
                },
            },
            KeyedHashScheme::Hmac { hmac_scheme } => TPMT_KEYEDHASH_SCHEME {
                scheme: KeyedHashSchemeAlgorithm::Hmac.into(),
                details: TPMU_SCHEME_KEYEDHASH {
                    hmac: hmac_scheme.into(),
                },
            },
            KeyedHashScheme::Null => TPMT_KEYEDHASH_SCHEME {
                scheme: KeyedHashSchemeAlgorithm::Null.into(),
                details: Default::default(),
            },
        }
    }
}

impl TryFrom<TPMT_KEYEDHASH_SCHEME> for KeyedHashScheme {
    type Error = Error;
    fn try_from(tpmt_keyedhash_scheme: TPMT_KEYEDHASH_SCHEME) -> Result<KeyedHashScheme> {
        match KeyedHashSchemeAlgorithm::try_from(tpmt_keyedhash_scheme.scheme)? {
            KeyedHashSchemeAlgorithm::Xor => Ok(KeyedHashScheme::Xor {
                xor_scheme: unsafe { tpmt_keyedhash_scheme.details.exclusiveOr }.try_into()?,
            }),
            KeyedHashSchemeAlgorithm::Hmac => Ok(KeyedHashScheme::Hmac {
                hmac_scheme: unsafe { tpmt_keyedhash_scheme.details.hmac }.try_into()?,
            }),
            KeyedHashSchemeAlgorithm::Null => Ok(KeyedHashScheme::Null),
        }
    }
}

/// Enum representing the rsa scheme
///
/// # Details
/// This corresponds to TPMT_RSA_SCHEME.
/// This uses a subset of the TPMU_ASYM_SCHEME
/// that has the TPMI_ALG_RSA_SCHEME as selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaScheme {
    RsaSsa(HashScheme),
    RsaEs,
    RsaPss(HashScheme),
    Oaep(HashScheme),
    Null,
}

impl RsaScheme {
    /// Creates a new RsaScheme
    ///
    /// # Arguments
    /// `rsa_scheme_algorithm` - The [RsaSchemeAlgorithm] associated with variant.
    /// `hashing_algorithm`    - A hashing algorithm that is required by some of the
    ///                          variants.
    ///
    /// # Errors
    /// `ParamMissing`       - If optional parameter is not provided when it is required.
    ///                        I.e. when creating RSA scheme of type RSA SSA, RSA PSS and
    ///                        OAEP.
    ///
    /// `InconsistentParams` - If the optional parameter has been provided when it is
    ///                        not required. I.e. if a hashing algorithm is provided
    ///                        when creating a the RSA scheme of type Null.
    pub fn create(
        rsa_scheme_algorithm: RsaSchemeAlgorithm,
        hashing_algorithm: Option<HashingAlgorithm>,
    ) -> Result<RsaScheme> {
        match rsa_scheme_algorithm {
            RsaSchemeAlgorithm::RsaSsa => Ok(RsaScheme::RsaSsa(HashScheme::new(
                hashing_algorithm.ok_or_else(|| {
                    error!(
                        "Hashing algorithm is required when creating RSA scheme of type RSA SSA"
                    );
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
            ))),
            RsaSchemeAlgorithm::RsaEs => {
                if hashing_algorithm.is_some() {
                    error!("A hashing algorithm shall not be provided when creating RSA scheme of type RSA ES");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                Ok(RsaScheme::RsaEs)
            }
            RsaSchemeAlgorithm::RsaPss => Ok(RsaScheme::RsaPss(HashScheme::new(
                hashing_algorithm.ok_or_else(|| {
                    error!(
                        "Hashing algorithm is required when creating RSA scheme of type RSA PSS"
                    );
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
            ))),
            RsaSchemeAlgorithm::Oaep => Ok(RsaScheme::Oaep(HashScheme::new(
                hashing_algorithm.ok_or_else(|| {
                    error!("Hashing algorithm is required when creating RSA scheme of type OAEP");
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
            ))),
            RsaSchemeAlgorithm::Null => {
                if hashing_algorithm.is_some() {
                    error!("A hashing algorithm shall not be provided when creating RSA scheme of type Null");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                Ok(RsaScheme::Null)
            }
        }
    }

    /// Returns the rsa scheme algorithm
    pub fn algorithm(&self) -> RsaSchemeAlgorithm {
        match self {
            RsaScheme::RsaSsa(_) => RsaSchemeAlgorithm::RsaSsa,
            RsaScheme::RsaEs => RsaSchemeAlgorithm::RsaEs,
            RsaScheme::RsaPss(_) => RsaSchemeAlgorithm::RsaPss,
            RsaScheme::Oaep(_) => RsaSchemeAlgorithm::Oaep,
            RsaScheme::Null => RsaSchemeAlgorithm::Null,
        }
    }
}

impl From<RsaScheme> for TPMT_RSA_SCHEME {
    fn from(rsa_scheme: RsaScheme) -> Self {
        match rsa_scheme {
            RsaScheme::RsaSsa(hash_scheme) => TPMT_RSA_SCHEME {
                scheme: rsa_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    rsassa: hash_scheme.into(),
                },
            },
            RsaScheme::RsaEs => TPMT_RSA_SCHEME {
                scheme: rsa_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    rsaes: Default::default(),
                },
            },
            RsaScheme::RsaPss(hash_scheme) => TPMT_RSA_SCHEME {
                scheme: rsa_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    rsapss: hash_scheme.into(),
                },
            },
            RsaScheme::Oaep(hash_scheme) => TPMT_RSA_SCHEME {
                scheme: rsa_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    oaep: hash_scheme.into(),
                },
            },
            RsaScheme::Null => TPMT_RSA_SCHEME {
                scheme: rsa_scheme.algorithm().into(),
                details: Default::default(),
            },
        }
    }
}

impl TryFrom<TPMT_RSA_SCHEME> for RsaScheme {
    type Error = Error;

    fn try_from(tpmt_rsa_scheme: TPMT_RSA_SCHEME) -> Result<Self> {
        match RsaSchemeAlgorithm::try_from(tpmt_rsa_scheme.scheme)? {
            RsaSchemeAlgorithm::RsaSsa => Ok(RsaScheme::RsaSsa(
                unsafe { tpmt_rsa_scheme.details.rsassa }.try_into()?,
            )),
            RsaSchemeAlgorithm::RsaEs => Ok(RsaScheme::RsaEs),
            RsaSchemeAlgorithm::RsaPss => Ok(RsaScheme::RsaPss(
                unsafe { tpmt_rsa_scheme.details.rsapss }.try_into()?,
            )),
            RsaSchemeAlgorithm::Oaep => Ok(RsaScheme::Oaep(
                unsafe { tpmt_rsa_scheme.details.oaep }.try_into()?,
            )),
            RsaSchemeAlgorithm::Null => Ok(RsaScheme::Null),
        }
    }
}

/// Enum representing the ecc scheme
///
/// # Details
/// This corresponds to TPMT_ECC_SCHEME.
/// This uses a subset of the TPMU_ASYM_SCHEME
/// that has the TPMI_ALG_ECC_SCHEME as selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EccScheme {
    EcDsa(HashScheme),
    EcDh(HashScheme),
    EcDaa(EcDaaScheme),
    Sm2(HashScheme),
    EcSchnorr(HashScheme),
    EcMqv(HashScheme),
    Null,
}

impl EccScheme {
    /// Creates a EccScheme.
    ///
    /// # Arguments
    /// `ecc_scheme_algorithm` - The ECC scheme algorithm.
    /// `hashing_algorithm` - The hashing algorithm associated with some variants.
    /// `count` - The counter value that is used between TPM2_Commit() and the sign
    ///           operation used in the EcDaa variant.
    ///
    /// # Errors
    /// `ParamMissing`       - If the algorithm indicates a variant that requires
    ///                        one or more of the optional parameters and they have
    ///                        not been provided.
    ///
    /// `InconsistentParams` - If an optional parameter has been set but it is
    ///                        not required.
    pub fn create(
        ecc_scheme_algorithm: EccSchemeAlgorithm,
        hashing_algorithm: Option<HashingAlgorithm>,
        count: Option<u16>,
    ) -> Result<Self> {
        match ecc_scheme_algorithm {
            EccSchemeAlgorithm::EcDsa => {
                if count.is_some() {
                    error!(
                        "`count` should not be provided when creating ECC scheme of type EC DSA."
                    );
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                hashing_algorithm
                    .ok_or_else(|| {
                        error!(
                            "Hashing algorithm is required when creating ECC scheme of type EC DSA."
                        );
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })
                    .map(|v| EccScheme::EcDsa(HashScheme::new(v)))
            }
            EccSchemeAlgorithm::EcDh => {
                if count.is_some() {
                    error!(
                        "`count` should not be provided when creating ECC scheme of type EC DH."
                    );
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                hashing_algorithm
                    .ok_or_else(|| {
                        error!(
                            "Hashing algorithm is required when creating ECC scheme of type EC DH."
                        );
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })
                    .map(|v| EccScheme::EcDh(HashScheme::new(v)))
            }
            EccSchemeAlgorithm::EcDaa => Ok(EccScheme::EcDaa(EcDaaScheme::new(
                hashing_algorithm.ok_or_else(|| {
                    error!(
                        "Hashing algorithm is required when creating ECC scheme of type EC DAA."
                    );
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
                count.ok_or_else(|| {
                    error!("Count is required when creating ECC scheme of type EC DAA.");
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
            ))),
            EccSchemeAlgorithm::Sm2 => {
                if count.is_some() {
                    error!("`count` should not be provided when creating ECC scheme of type SM2.");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                hashing_algorithm
                    .ok_or_else(|| {
                        error!(
                            "Hashing algorithm is required when creating ECC scheme of type SM2."
                        );
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })
                    .map(|v| EccScheme::Sm2(HashScheme::new(v)))
            }
            EccSchemeAlgorithm::EcSchnorr => {
                if count.is_some() {
                    error!("`count` should not be provided when creating ECC scheme of type EC SCHNORR.");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                hashing_algorithm
                    .ok_or_else(|| {
                        error!(
                            "Hashing algorithm is required when creating ECC scheme of type EC SCHNORR."
                        );
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })
                    .map(|v| EccScheme::EcSchnorr(HashScheme::new(v)))
            }
            EccSchemeAlgorithm::EcMqv => {
                if count.is_some() {
                    error!(
                        "`count` should not be provided when creating ECC scheme of type EC MQV."
                    );
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                hashing_algorithm
                    .ok_or_else(|| {
                        error!(
                            "Hashing algorithm is required when creating ECC scheme of type EC MQV."
                        );
                        Error::local_error(WrapperErrorKind::ParamsMissing)
                    })
                    .map(|v| EccScheme::EcMqv(HashScheme::new(v)))
            }
            EccSchemeAlgorithm::Null => {
                if count.is_some() {
                    error!("`count` should not be provided when creating ECC scheme of type Null.");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                if hashing_algorithm.is_some() {
                    error!("A hashing algorithm shall not be provided when creating ECC scheme of type Null.");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                Ok(EccScheme::Null)
            }
        }
    }

    pub fn algorithm(&self) -> EccSchemeAlgorithm {
        match self {
            EccScheme::EcDsa(_) => EccSchemeAlgorithm::EcDsa,
            EccScheme::EcDh(_) => EccSchemeAlgorithm::EcDh,
            EccScheme::EcDaa(_) => EccSchemeAlgorithm::EcDaa,
            EccScheme::Sm2(_) => EccSchemeAlgorithm::Sm2,
            EccScheme::EcSchnorr(_) => EccSchemeAlgorithm::EcSchnorr,
            EccScheme::EcMqv(_) => EccSchemeAlgorithm::EcMqv,
            EccScheme::Null => EccSchemeAlgorithm::Null,
        }
    }
}

impl From<EccScheme> for TPMT_ECC_SCHEME {
    fn from(ecc_scheme: EccScheme) -> Self {
        match ecc_scheme {
            EccScheme::EcDsa(hash_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    ecdsa: hash_scheme.into(),
                },
            },
            EccScheme::EcDh(hash_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    ecdh: hash_scheme.into(),
                },
            },
            EccScheme::EcDaa(ec_daa_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    ecdaa: ec_daa_scheme.into(),
                },
            },

            EccScheme::Sm2(hash_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    sm2: hash_scheme.into(),
                },
            },
            EccScheme::EcSchnorr(hash_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    ecschnorr: hash_scheme.into(),
                },
            },
            EccScheme::EcMqv(hash_scheme) => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    ecmqv: hash_scheme.into(),
                },
            },
            EccScheme::Null => TPMT_ECC_SCHEME {
                scheme: ecc_scheme.algorithm().into(),
                details: Default::default(),
            },
        }
    }
}

impl TryFrom<TPMT_ECC_SCHEME> for EccScheme {
    type Error = Error;

    fn try_from(tpmt_ecc_scheme: TPMT_ECC_SCHEME) -> Result<Self> {
        match EccSchemeAlgorithm::try_from(tpmt_ecc_scheme.scheme)? {
            EccSchemeAlgorithm::EcDsa => Ok(EccScheme::EcDsa(
                unsafe { tpmt_ecc_scheme.details.ecdsa }.try_into()?,
            )),
            EccSchemeAlgorithm::EcDh => Ok(EccScheme::EcDh(
                unsafe { tpmt_ecc_scheme.details.ecdh }.try_into()?,
            )),
            EccSchemeAlgorithm::EcDaa => Ok(EccScheme::EcDaa(
                unsafe { tpmt_ecc_scheme.details.ecdaa }.try_into()?,
            )),
            EccSchemeAlgorithm::Sm2 => Ok(EccScheme::Sm2(
                unsafe { tpmt_ecc_scheme.details.sm2 }.try_into()?,
            )),
            EccSchemeAlgorithm::EcSchnorr => Ok(EccScheme::EcSchnorr(
                unsafe { tpmt_ecc_scheme.details.ecschnorr }.try_into()?,
            )),
            EccSchemeAlgorithm::EcMqv => Ok(EccScheme::EcMqv(
                unsafe { tpmt_ecc_scheme.details.ecmqv }.try_into()?,
            )),
            EccSchemeAlgorithm::Null => Ok(EccScheme::Null),
        }
    }
}

/// Enum representing the kdf scheme
///
/// # Details
/// This corresponds to TPMT_KDF_SCHEME.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyDerivationFunctionScheme {
    Kdf1Sp800_56a(HashScheme),
    Kdf2(HashScheme),
    Kdf1Sp800_108(HashScheme),
    Mgf1(HashScheme),
    Null,
}

impl From<KeyDerivationFunctionScheme> for TPMT_KDF_SCHEME {
    fn from(key_derivation_function_scheme: KeyDerivationFunctionScheme) -> Self {
        match key_derivation_function_scheme {
            KeyDerivationFunctionScheme::Kdf1Sp800_56a(hash_scheme) => TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::Kdf1Sp800_56a.into(),
                details: TPMU_KDF_SCHEME {
                    kdf1_sp800_56a: hash_scheme.into(),
                },
            },
            KeyDerivationFunctionScheme::Kdf2(hash_scheme) => TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::Kdf2.into(),
                details: TPMU_KDF_SCHEME {
                    kdf2: hash_scheme.into(),
                },
            },
            KeyDerivationFunctionScheme::Kdf1Sp800_108(hash_scheme) => TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::Kdf1Sp800_108.into(),
                details: TPMU_KDF_SCHEME {
                    kdf1_sp800_108: hash_scheme.into(),
                },
            },
            KeyDerivationFunctionScheme::Mgf1(hash_scheme) => TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::Mgf1.into(),
                details: TPMU_KDF_SCHEME {
                    mgf1: hash_scheme.into(),
                },
            },
            KeyDerivationFunctionScheme::Null => TPMT_KDF_SCHEME {
                scheme: KeyDerivationFunction::Null.into(),
                details: Default::default(),
            },
        }
    }
}

impl TryFrom<TPMT_KDF_SCHEME> for KeyDerivationFunctionScheme {
    type Error = Error;

    fn try_from(tpmt_kdf_scheme: TPMT_KDF_SCHEME) -> Result<Self> {
        match KeyDerivationFunction::try_from(tpmt_kdf_scheme.scheme)? {
            KeyDerivationFunction::Kdf1Sp800_56a => Ok(KeyDerivationFunctionScheme::Kdf1Sp800_56a(
                unsafe { tpmt_kdf_scheme.details.kdf1_sp800_56a }.try_into()?,
            )),
            KeyDerivationFunction::Kdf2 => Ok(KeyDerivationFunctionScheme::Kdf2(
                unsafe { tpmt_kdf_scheme.details.kdf2 }.try_into()?,
            )),
            KeyDerivationFunction::Kdf1Sp800_108 => Ok(KeyDerivationFunctionScheme::Kdf1Sp800_108(
                unsafe { tpmt_kdf_scheme.details.kdf1_sp800_108 }.try_into()?,
            )),
            KeyDerivationFunction::Mgf1 => Ok(KeyDerivationFunctionScheme::Mgf1(
                unsafe { tpmt_kdf_scheme.details.mgf1 }.try_into()?,
            )),
            KeyDerivationFunction::Null => Ok(KeyDerivationFunctionScheme::Null),
        }
    }
}

/// Enum representing the rsa decryption scheme
///
/// # Details
/// This corresponds to TPMT_RSA_DECRYPT.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsaDecryptionScheme {
    RsaEs,
    Oaep(HashScheme),
    Null,
}

impl RsaDecryptionScheme {
    /// Creates a new rsa decrypt scheme.
    ///
    /// # Arguments
    /// `rsa_decrypt_algorithm` - The RSA decryption algorithm.
    /// `hashing_algorithm` - The hashing algorithm used in some variants of the scheme.
    ///
    /// # Errors
    /// `InconsistentParams` - If a parameter has been provided when it is not required.
    /// `ParamsMissing` - If a required parameter has not been provided.
    pub fn create(
        rsa_decrypt_algorithm: RsaDecryptAlgorithm,
        hashing_algorithm: Option<HashingAlgorithm>,
    ) -> Result<RsaDecryptionScheme> {
        match rsa_decrypt_algorithm {
            RsaDecryptAlgorithm::RsaEs => {
                if hashing_algorithm.is_none() {
                    Ok(RsaDecryptionScheme::RsaEs)
                } else {
                    error!("A hashing algorithm shall not be provided when creating RSA decryption scheme of type RSA ES");
                    Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                }
            },
            RsaDecryptAlgorithm::Oaep => Ok(RsaDecryptionScheme::Oaep(HashScheme::new(
                hashing_algorithm.ok_or_else(|| {
                    error!("Hashing algorithm is required when creating RSA decrypt scheme of type OEAP");
                    Error::local_error(WrapperErrorKind::ParamsMissing)
                })?,
            ))),
            RsaDecryptAlgorithm::Null => {
                if hashing_algorithm.is_none() {
                    Ok(RsaDecryptionScheme::Null)
                } else {
                    error!("A hashing algorithm shall not be provided when creating RSA decryption scheme of type Null");
                    Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                }
            }
        }
    }

    /// Returns the rsa decrypt scheme algorithm
    pub fn algorithm(&self) -> RsaDecryptAlgorithm {
        match self {
            RsaDecryptionScheme::RsaEs => RsaDecryptAlgorithm::RsaEs,
            RsaDecryptionScheme::Oaep(_) => RsaDecryptAlgorithm::Oaep,
            RsaDecryptionScheme::Null => RsaDecryptAlgorithm::Null,
        }
    }
}

impl From<RsaDecryptionScheme> for TPMT_RSA_DECRYPT {
    fn from(rsa_decryption_scheme: RsaDecryptionScheme) -> Self {
        match rsa_decryption_scheme {
            RsaDecryptionScheme::RsaEs => TPMT_RSA_DECRYPT {
                scheme: rsa_decryption_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    rsaes: Default::default(),
                },
            },
            RsaDecryptionScheme::Oaep(hash_scheme) => TPMT_RSA_DECRYPT {
                scheme: rsa_decryption_scheme.algorithm().into(),
                details: TPMU_ASYM_SCHEME {
                    oaep: hash_scheme.into(),
                },
            },
            RsaDecryptionScheme::Null => TPMT_RSA_DECRYPT {
                scheme: rsa_decryption_scheme.algorithm().into(),
                details: Default::default(),
            },
        }
    }
}

impl TryFrom<TPMT_RSA_DECRYPT> for RsaDecryptionScheme {
    type Error = Error;

    fn try_from(tpmt_rsa_decrypt: TPMT_RSA_DECRYPT) -> Result<Self> {
        match RsaDecryptAlgorithm::try_from(tpmt_rsa_decrypt.scheme)? {
            RsaDecryptAlgorithm::RsaEs => Ok(RsaDecryptionScheme::RsaEs),
            RsaDecryptAlgorithm::Oaep => Ok(RsaDecryptionScheme::Oaep(
                unsafe { tpmt_rsa_decrypt.details.oaep }.try_into()?,
            )),
            RsaDecryptAlgorithm::Null => Ok(RsaDecryptionScheme::Null),
        }
    }
}

impl TryFrom<RsaScheme> for RsaDecryptionScheme {
    type Error = Error;

    fn try_from(rsa_scheme: RsaScheme) -> Result<Self> {
        match rsa_scheme {
            RsaScheme::RsaEs => Ok(RsaDecryptionScheme::RsaEs),
            RsaScheme::Oaep(hash_scheme) => Ok(RsaDecryptionScheme::Oaep(hash_scheme)),
            RsaScheme::Null => Ok(RsaDecryptionScheme::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// Full description of signature schemes.
///
/// # Details
/// Corresponds to `TPMT_SIG_SCHEME`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureScheme {
    RsaSsa { scheme: HashScheme },
    RsaPss { scheme: HashScheme },
    EcDsa { scheme: HashScheme },
    Sm2 { scheme: HashScheme },
    EcSchnorr { scheme: HashScheme },
    EcDaa { scheme: EcDaaScheme },
    Hmac { scheme: HmacScheme },
    Null,
}

impl SignatureScheme {
    /// Returns the digest( i.e. hashing algorithm) of a signing scheme.
    ///
    /// # Details
    /// This is intended to provide the functionality of reading
    /// from the `any` field in the TPMU_SIG_SCHEME union.
    ///
    /// # Errors
    /// Returns an InvalidParam error if the trying to read from
    /// SignatureScheme that is not a signing scheme.
    pub fn signing_scheme(&self) -> Result<HashingAlgorithm> {
        match self {
            SignatureScheme::RsaSsa { scheme }
            | SignatureScheme::RsaPss { scheme }
            | SignatureScheme::EcDsa { scheme }
            | SignatureScheme::Sm2 { scheme }
            | SignatureScheme::EcSchnorr { scheme } => Ok(scheme.hashing_algorithm()),
            SignatureScheme::EcDaa { scheme } => Ok(scheme.hashing_algorithm()),
            SignatureScheme::Hmac { scheme } => Ok(scheme.hashing_algorithm()),
            _ => {
                error!("Cannot access digest for a non signing scheme");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }

    /// Sets digest( i.e. hashing algorithm) of a signing scheme.
    ///
    /// # Details
    /// This is intended to provide the functionality of writing
    /// to the `any` field in the TPMU_SIG_SCHEME union.
    ///
    /// # Errors
    /// Returns an InvalidParam error if the trying to read from
    /// SignatureScheme that is not a signing scheme.
    pub fn set_signing_scheme(&mut self, hashing_algorithm: HashingAlgorithm) -> Result<()> {
        match self {
            SignatureScheme::RsaSsa { scheme }
            | SignatureScheme::RsaPss { scheme }
            | SignatureScheme::EcDsa { scheme }
            | SignatureScheme::Sm2 { scheme }
            | SignatureScheme::EcSchnorr { scheme } => {
                *scheme = HashScheme::new(hashing_algorithm);
                Ok(())
            }
            SignatureScheme::EcDaa { scheme } => {
                *scheme = EcDaaScheme::new(hashing_algorithm, scheme.count());
                Ok(())
            }
            SignatureScheme::Hmac { scheme } => {
                *scheme = HmacScheme::new(hashing_algorithm);
                Ok(())
            }
            _ => {
                error!("Cannot access digest for a non signing scheme");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

impl From<SignatureScheme> for TPMT_SIG_SCHEME {
    fn from(native: SignatureScheme) -> TPMT_SIG_SCHEME {
        match native {
            SignatureScheme::EcDaa { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::EcDaa.into(),
                details: TPMU_SIG_SCHEME {
                    ecdaa: scheme.into(),
                },
            },
            SignatureScheme::EcDsa { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::EcDsa.into(),
                details: TPMU_SIG_SCHEME {
                    ecdsa: scheme.into(),
                },
            },
            SignatureScheme::EcSchnorr { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::EcSchnorr.into(),
                details: TPMU_SIG_SCHEME {
                    ecschnorr: scheme.into(),
                },
            },
            SignatureScheme::Hmac { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::Hmac.into(),
                details: TPMU_SIG_SCHEME {
                    hmac: scheme.into(),
                },
            },
            SignatureScheme::Null => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::Null.into(),
                details: Default::default(),
            },
            SignatureScheme::RsaPss { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::RsaPss.into(),
                details: TPMU_SIG_SCHEME {
                    rsapss: scheme.into(),
                },
            },
            SignatureScheme::RsaSsa { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::RsaSsa.into(),
                details: TPMU_SIG_SCHEME {
                    rsassa: scheme.into(),
                },
            },
            SignatureScheme::Sm2 { scheme } => TPMT_SIG_SCHEME {
                scheme: SignatureSchemeAlgorithm::Sm2.into(),
                details: TPMU_SIG_SCHEME { sm2: scheme.into() },
            },
        }
    }
}

impl TryFrom<TPMT_SIG_SCHEME> for SignatureScheme {
    type Error = Error;

    fn try_from(tss: TPMT_SIG_SCHEME) -> Result<Self> {
        match SignatureSchemeAlgorithm::try_from(tss.scheme)? {
            SignatureSchemeAlgorithm::EcDaa => Ok(SignatureScheme::EcDaa {
                scheme: unsafe { tss.details.ecdaa }.try_into()?,
            }),
            SignatureSchemeAlgorithm::EcDsa => Ok(SignatureScheme::EcDsa {
                scheme: unsafe { tss.details.ecdsa }.try_into()?,
            }),
            SignatureSchemeAlgorithm::EcSchnorr => Ok(SignatureScheme::EcSchnorr {
                scheme: unsafe { tss.details.ecschnorr }.try_into()?,
            }),
            SignatureSchemeAlgorithm::Hmac => Ok(SignatureScheme::Hmac {
                scheme: unsafe { tss.details.hmac }.try_into()?,
            }),
            SignatureSchemeAlgorithm::Null => Ok(SignatureScheme::Null),
            SignatureSchemeAlgorithm::RsaPss => Ok(SignatureScheme::RsaPss {
                scheme: unsafe { tss.details.rsapss }.try_into()?,
            }),
            SignatureSchemeAlgorithm::RsaSsa => Ok(SignatureScheme::RsaSsa {
                scheme: unsafe { tss.details.rsassa }.try_into()?,
            }),
            SignatureSchemeAlgorithm::Sm2 => Ok(SignatureScheme::Sm2 {
                scheme: unsafe { tss.details.sm2 }.try_into()?,
            }),
        }
    }
}
