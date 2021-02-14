// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::{HashingAlgorithm, KeyedHashSchemeAlgorithm},
    structures::schemes::{HmacScheme, XorScheme},
    tss2_esys::{TPMT_KEYEDHASH_SCHEME, TPMU_SCHEME_KEYEDHASH},
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
