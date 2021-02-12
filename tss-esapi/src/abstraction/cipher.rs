// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::Algorithm,
    interface_types::algorithm::{HashingAlgorithm, SymmetricAlgorithm, SymmetricMode},
    tss2_esys::{TPMS_SYMCIPHER_PARMS, TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT},
    utils::TpmtSymDefBuilder,
    Error, Result, WrapperErrorKind,
};
/// Block cipher identifiers
///
/// Structure useful for handling an abstract representation of ciphers. Ciphers are
/// defined foremost through their symmetric algorithm and, depending on the type of that
/// algorithm, on a set of other values.
#[derive(Copy, Clone, Debug)]
pub struct Cipher {
    algorithm: SymmetricAlgorithm,
    mode: Option<SymmetricMode>,
    key_bits: Option<u16>,
    hash: Option<HashingAlgorithm>,
}

impl Cipher {
    /// Constructor for AES cipher identifier
    ///
    /// `key_bits` must be one of 128, 192 or 256.
    pub fn aes(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
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
    pub fn camellia(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
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
    pub fn tdes(mode: SymmetricMode, key_bits: u16) -> Result<Self> {
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
    pub fn sm4(mode: SymmetricMode) -> Self {
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
    pub fn object_type() -> Algorithm {
        Algorithm::SymCipher
    }

    /// Get the cipher key length.
    pub fn key_bits(self) -> Option<u16> {
        self.key_bits
    }

    /// Get the cipher mode.
    pub fn mode(self) -> Option<SymmetricMode> {
        self.mode
    }

    /// Get the hash algorithm used with an XOR cipher
    pub fn hash(self) -> Option<HashingAlgorithm> {
        self.hash
    }

    /// Get the symmetrical algorithm for the cipher.
    pub fn algorithm(&self) -> SymmetricAlgorithm {
        self.algorithm
    }
    // /// Get the TSS algorithm ID.
    // pub fn algorithm_id(self) -> TPM2_ALG_ID {
    //     self.algorithm.into()
    // }

    /// Constructor for 128 bit AES in CFB mode.
    pub fn aes_128_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(SymmetricMode::Cfb),
            key_bits: Some(128),
            hash: None,
        }
    }

    /// Constructor for 256 bit AES in CFB mode.
    pub fn aes_256_cfb() -> Self {
        Cipher {
            algorithm: SymmetricAlgorithm::Aes,
            mode: Some(SymmetricMode::Cfb),
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
            Algorithm::Null.into()
        };

        let mode = if let Some(mode) = cipher.mode {
            mode.into()
        } else {
            Algorithm::Null.into()
        };

        TpmtSymDefBuilder::new()
            .with_algorithm(Algorithm::from(cipher.algorithm()).into())
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
            Algorithm::Null.into()
        };

        let mode = if let Some(mode) = cipher.mode {
            mode.into()
        } else {
            Algorithm::Null.into()
        };

        TpmtSymDefBuilder::new()
            .with_algorithm(Algorithm::from(cipher.algorithm()).into())
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
