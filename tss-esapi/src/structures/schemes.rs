// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::{HashingAlgorithm, KeyDerivationFunction},
    tss2_esys::{TPMS_SCHEME_ECDAA, TPMS_SCHEME_HASH, TPMS_SCHEME_HMAC, TPMS_SCHEME_XOR},
    Error, Result,
};
use std::convert::{TryFrom, TryInto};
/// Struct for holding the hash scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HashScheme {
    hashing_algorithm: HashingAlgorithm,
}

impl HashScheme {
    /// Creates a new HashScheme
    pub const fn new(hashing_algorithm: HashingAlgorithm) -> HashScheme {
        HashScheme { hashing_algorithm }
    }
}

impl TryFrom<TPMS_SCHEME_HASH> for HashScheme {
    type Error = Error;
    fn try_from(tpms_scheme_hash: TPMS_SCHEME_HASH) -> Result<Self> {
        Ok(HashScheme {
            hashing_algorithm: tpms_scheme_hash.hashAlg.try_into()?,
        })
    }
}

impl From<HashScheme> for TPMS_SCHEME_HASH {
    fn from(hash_scheme: HashScheme) -> Self {
        TPMS_SCHEME_HASH {
            hashAlg: hash_scheme.hashing_algorithm.into(),
        }
    }
}

/// Struct for holding HMAC scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HmacScheme {
    hashing_algorithm: HashingAlgorithm,
}

impl HmacScheme {
    /// Creates a new HmacScheme
    pub const fn new(hashing_algorithm: HashingAlgorithm) -> HmacScheme {
        HmacScheme { hashing_algorithm }
    }
}

impl From<HashScheme> for HmacScheme {
    fn from(hash_scheme: HashScheme) -> Self {
        HmacScheme {
            hashing_algorithm: hash_scheme.hashing_algorithm,
        }
    }
}

impl From<HmacScheme> for HashScheme {
    fn from(hmac_scheme: HmacScheme) -> Self {
        HashScheme {
            hashing_algorithm: hmac_scheme.hashing_algorithm,
        }
    }
}

impl TryFrom<TPMS_SCHEME_HMAC> for HmacScheme {
    type Error = Error;
    fn try_from(tpms_scheme_hmac: TPMS_SCHEME_HMAC) -> Result<Self> {
        Ok(HmacScheme {
            hashing_algorithm: tpms_scheme_hmac.hashAlg.try_into()?,
        })
    }
}

impl From<HmacScheme> for TPMS_SCHEME_HMAC {
    fn from(hash_scheme: HmacScheme) -> Self {
        TPMS_SCHEME_HMAC {
            hashAlg: hash_scheme.hashing_algorithm.into(),
        }
    }
}

/// Struct for holding the xor scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XorScheme {
    hashing_algorithm: HashingAlgorithm,
    key_derivation_function: KeyDerivationFunction,
}

impl XorScheme {
    /// Creates a new XorScheme
    pub const fn new(
        hashing_algorithm: HashingAlgorithm,
        key_derivation_function: KeyDerivationFunction,
    ) -> XorScheme {
        XorScheme {
            hashing_algorithm,
            key_derivation_function,
        }
    }
}

impl TryFrom<TPMS_SCHEME_XOR> for XorScheme {
    type Error = Error;
    fn try_from(tpms_scheme_xor: TPMS_SCHEME_XOR) -> Result<Self> {
        Ok(XorScheme {
            hashing_algorithm: tpms_scheme_xor.hashAlg.try_into()?,
            key_derivation_function: tpms_scheme_xor.kdf.try_into()?,
        })
    }
}

impl From<XorScheme> for TPMS_SCHEME_XOR {
    fn from(xor_scheme: XorScheme) -> Self {
        TPMS_SCHEME_XOR {
            hashAlg: xor_scheme.hashing_algorithm.into(),
            kdf: xor_scheme.key_derivation_function.into(),
        }
    }
}

/// Struct for holding ECDAA scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EcdaaScheme {
    hashing_algorithm: HashingAlgorithm,
    count: u16,
}

impl EcdaaScheme {
    pub const fn new(hashing_algorithm: HashingAlgorithm, count: u16) -> Self {
        EcdaaScheme {
            hashing_algorithm,
            count,
        }
    }
}

impl From<EcdaaScheme> for TPMS_SCHEME_ECDAA {
    fn from(native: EcdaaScheme) -> Self {
        TPMS_SCHEME_ECDAA {
            hashAlg: native.hashing_algorithm.into(),
            count: native.count,
        }
    }
}

impl TryFrom<TPMS_SCHEME_ECDAA> for EcdaaScheme {
    type Error = Error;

    fn try_from(tss: TPMS_SCHEME_ECDAA) -> Result<Self> {
        Ok(EcdaaScheme {
            hashing_algorithm: tss.hashAlg.try_into()?,
            count: tss.count,
        })
    }
}
