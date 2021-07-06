// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::{self, HashingAlgorithm, KeyedHashSchemeAlgorithm},
    structures::schemes::{EcdaaScheme, HashScheme, HmacScheme, XorScheme},
    tss2_esys::{TPMT_KEYEDHASH_SCHEME, TPMT_SIG_SCHEME, TPMU_SCHEME_KEYEDHASH, TPMU_SIG_SCHEME},
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// Enum representing the keyed hash scheme.
///
/// # Details
/// This corresponds to TPMT_SCHEME_KEYEDHASH.
#[derive(Clone, Copy, Debug)]
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

/// Full description of signature schemes.
///
/// # Details
/// Corresponds to `TPMT_SIG_SCHEME`.
#[derive(Clone, Copy, Debug)]
pub enum SignatureScheme {
    RsaSsa { hash_scheme: HashScheme },
    RsaPss { hash_scheme: HashScheme },
    EcDsa { hash_scheme: HashScheme },
    Sm2 { hash_scheme: HashScheme },
    EcSchnorr { hash_scheme: HashScheme },
    EcDaa { ecdaa_scheme: EcdaaScheme },
    Hmac { hmac_scheme: HmacScheme },
    Null { hash_scheme: HashScheme },
}

impl SignatureScheme {
    /// Null scheme, representing "no scheme" or "default"
    pub const NULL: SignatureScheme = SignatureScheme::Null {
        hash_scheme: HashScheme::new(HashingAlgorithm::Null),
    };
}

impl From<SignatureScheme> for TPMT_SIG_SCHEME {
    fn from(native: SignatureScheme) -> TPMT_SIG_SCHEME {
        match native {
            SignatureScheme::EcDaa { ecdaa_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::EcDaa.into(),
                details: TPMU_SIG_SCHEME {
                    ecdaa: ecdaa_scheme.into(),
                },
            },
            SignatureScheme::EcDsa { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::EcDsa.into(),
                details: TPMU_SIG_SCHEME {
                    ecdsa: hash_scheme.into(),
                },
            },
            SignatureScheme::EcSchnorr { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::EcSchnorr.into(),
                details: TPMU_SIG_SCHEME {
                    ecschnorr: hash_scheme.into(),
                },
            },
            SignatureScheme::Hmac { hmac_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::Hmac.into(),
                details: TPMU_SIG_SCHEME {
                    hmac: hmac_scheme.into(),
                },
            },
            SignatureScheme::Null { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::Null.into(),
                details: TPMU_SIG_SCHEME {
                    any: hash_scheme.into(),
                },
            },
            SignatureScheme::RsaPss { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::RsaPss.into(),
                details: TPMU_SIG_SCHEME {
                    rsapss: hash_scheme.into(),
                },
            },
            SignatureScheme::RsaSsa { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::RsaSsa.into(),
                details: TPMU_SIG_SCHEME {
                    rsassa: hash_scheme.into(),
                },
            },
            SignatureScheme::Sm2 { hash_scheme } => TPMT_SIG_SCHEME {
                scheme: algorithm::SignatureScheme::Sm2.into(),
                details: TPMU_SIG_SCHEME {
                    sm2: hash_scheme.into(),
                },
            },
        }
    }
}

impl TryFrom<TPMT_SIG_SCHEME> for SignatureScheme {
    type Error = Error;

    fn try_from(tss: TPMT_SIG_SCHEME) -> Result<Self> {
        match algorithm::SignatureScheme::try_from(tss.scheme)? {
            algorithm::SignatureScheme::EcDaa => Ok(SignatureScheme::EcDaa {
                ecdaa_scheme: unsafe { tss.details.ecdaa }.try_into()?,
            }),
            algorithm::SignatureScheme::EcDsa => Ok(SignatureScheme::EcDsa {
                hash_scheme: unsafe { tss.details.ecdsa }.try_into()?,
            }),
            algorithm::SignatureScheme::EcSchnorr => Ok(SignatureScheme::EcSchnorr {
                hash_scheme: unsafe { tss.details.ecschnorr }.try_into()?,
            }),
            algorithm::SignatureScheme::Hmac => Ok(SignatureScheme::Hmac {
                hmac_scheme: unsafe { tss.details.hmac }.try_into()?,
            }),
            algorithm::SignatureScheme::Null => Ok(SignatureScheme::Null {
                hash_scheme: unsafe { tss.details.any }.try_into()?,
            }),
            algorithm::SignatureScheme::RsaPss => Ok(SignatureScheme::RsaPss {
                hash_scheme: unsafe { tss.details.rsapss }.try_into()?,
            }),
            algorithm::SignatureScheme::RsaSsa => Ok(SignatureScheme::RsaSsa {
                hash_scheme: unsafe { tss.details.rsassa }.try_into()?,
            }),
            algorithm::SignatureScheme::Sm2 => Ok(SignatureScheme::Sm2 {
                hash_scheme: unsafe { tss.details.sm2 }.try_into()?,
            }),
        }
    }
}
