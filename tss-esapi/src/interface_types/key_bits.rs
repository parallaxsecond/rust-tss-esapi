// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    tss2_esys::{TPMI_AES_KEY_BITS, TPMI_CAMELLIA_KEY_BITS, TPMI_SM4_KEY_BITS},
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// AES key bits interface type
///
/// # Details
/// This corresponds to TPMI_AES_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum AesKeyBits {
    Aes128,
    Aes192,
    Aes256,
}

impl From<AesKeyBits> for TPMI_AES_KEY_BITS {
    fn from(aes_key_bits: AesKeyBits) -> TPMI_AES_KEY_BITS {
        match aes_key_bits {
            AesKeyBits::Aes128 => 128,
            AesKeyBits::Aes192 => 192,
            AesKeyBits::Aes256 => 256,
        }
    }
}

impl TryFrom<TPMI_AES_KEY_BITS> for AesKeyBits {
    type Error = Error;
    fn try_from(tpmi_aes_key_bits: TPMI_AES_KEY_BITS) -> Result<AesKeyBits> {
        match tpmi_aes_key_bits {
            128 => Ok(AesKeyBits::Aes128),
            192 => Ok(AesKeyBits::Aes192),
            256 => Ok(AesKeyBits::Aes256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// SM4 key bits interface type
///
/// # Details
/// This corresponds to TPMI_SM4_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Sm4KeyBits {
    Sm4_128,
}

impl From<Sm4KeyBits> for TPMI_SM4_KEY_BITS {
    fn from(sm4_key_bits: Sm4KeyBits) -> TPMI_SM4_KEY_BITS {
        match sm4_key_bits {
            Sm4KeyBits::Sm4_128 => 128,
        }
    }
}

impl TryFrom<TPMI_SM4_KEY_BITS> for Sm4KeyBits {
    type Error = Error;
    fn try_from(tpmi_sm4_key_bits: TPMI_SM4_KEY_BITS) -> Result<Sm4KeyBits> {
        match tpmi_sm4_key_bits {
            128 => Ok(Sm4KeyBits::Sm4_128),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// Camellia key bits interface type
///
/// # Details
/// This corresponds to TPMI_CAMELLIA_KEY_BITS
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum CamelliaKeyBits {
    Camellia128,
    Camellia192,
    Camellia256,
}

impl From<CamelliaKeyBits> for TPMI_CAMELLIA_KEY_BITS {
    fn from(camellia_key_bits: CamelliaKeyBits) -> TPMI_CAMELLIA_KEY_BITS {
        match camellia_key_bits {
            CamelliaKeyBits::Camellia128 => 128,
            CamelliaKeyBits::Camellia192 => 192,
            CamelliaKeyBits::Camellia256 => 256,
        }
    }
}

impl TryFrom<TPMI_CAMELLIA_KEY_BITS> for CamelliaKeyBits {
    type Error = Error;
    fn try_from(tpmi_camellia_key_bits: TPMI_CAMELLIA_KEY_BITS) -> Result<CamelliaKeyBits> {
        match tpmi_camellia_key_bits {
            128 => Ok(CamelliaKeyBits::Camellia128),
            192 => Ok(CamelliaKeyBits::Camellia192),
            256 => Ok(CamelliaKeyBits::Camellia256),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
