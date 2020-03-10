// Copyright (c) 2020, Arm Limited, All Rights Reserved
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
use crate::constants::*;
use crate::tss2_esys::*;
use crate::utils::TpmtSymDefBuilder;

#[derive(Copy, Clone, Debug)]
pub enum Cipher {
    AES {
        key_bits: CipherKeyLength,
        mode: CipherMode,
    },
    XOR {
        hash: TPM2_ALG_ID,
    },
    SM4 {
        mode: CipherMode,
    },
    Camellia {
        key_bits: CipherKeyLength,
        mode: CipherMode,
    },
}

impl Cipher {
    pub fn object_type() -> TPM2_ALG_ID {
        TPM2_ALG_SYMCIPHER
    }

    pub fn key_bits(self) -> Option<CipherKeyLength> {
        match self {
            Cipher::AES { key_bits, .. } => Some(key_bits),
            Cipher::Camellia { key_bits, .. } => Some(key_bits),
            Cipher::SM4 { .. } => Some(CipherKeyLength::Bits128),
            Cipher::XOR { .. } => None,
        }
    }

    pub fn mode(self) -> Option<CipherMode> {
        match self {
            Cipher::AES { mode, .. } => Some(mode),
            Cipher::Camellia { mode, .. } => Some(mode),
            Cipher::SM4 { mode, .. } => Some(mode),
            Cipher::XOR { .. } => None,
        }
    }

    pub fn algorithm_id(self) -> TPM2_ALG_ID {
        match self {
            Cipher::AES { .. } => TPM2_ALG_AES,
            Cipher::Camellia { .. } => TPM2_ALG_CAMELLIA,
            Cipher::SM4 { .. } => TPM2_ALG_SM4,
            Cipher::XOR { .. } => TPM2_ALG_XOR,
        }
    }

    pub fn aes_128_cfb() -> Self {
        Cipher::AES {
            key_bits: CipherKeyLength::Bits128,
            mode: CipherMode::CFB,
        }
    }

    pub fn aes_256_cfb() -> Self {
        Cipher::AES {
            key_bits: CipherKeyLength::Bits256,
            mode: CipherMode::CFB,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CipherKeyLength {
    Bits128,
    Bits192,
    Bits256,
}

impl From<CipherKeyLength> for u16 {
    fn from(len: CipherKeyLength) -> Self {
        match len {
            CipherKeyLength::Bits128 => 128,
            CipherKeyLength::Bits192 => 192,
            CipherKeyLength::Bits256 => 256,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum CipherMode {
    CTR,
    OFB,
    CBC,
    CFB,
    ECB,
}

impl From<CipherMode> for TPM2_ALG_ID {
    fn from(mode: CipherMode) -> Self {
        match mode {
            CipherMode::CTR => TPM2_ALG_CTR,
            CipherMode::OFB => TPM2_ALG_OFB,
            CipherMode::CBC => TPM2_ALG_CBC,
            CipherMode::CFB => TPM2_ALG_CFB,
            CipherMode::ECB => TPM2_ALG_ECB,
        }
    }
}

impl From<Cipher> for TPMT_SYM_DEF {
    fn from(cipher: Cipher) -> Self {
        let key_bits = match cipher {
            Cipher::XOR { hash } => hash,
            _ => cipher.key_bits().unwrap().into(), // should not fail since XOR is covered above
        };

        let mode = match cipher {
            Cipher::XOR { .. } => TPM2_ALG_NULL,
            _ => cipher.mode().unwrap().into(), // should not fail since XOR is covered above
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
        let key_bits = match cipher {
            Cipher::XOR { hash } => hash,
            _ => cipher.key_bits().unwrap().into(), // should not fail since XOR is covered above
        };

        let mode = match cipher {
            Cipher::XOR { .. } => TPM2_ALG_NULL,
            _ => cipher.mode().unwrap().into(), // should not fail since XOR is covered above
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
