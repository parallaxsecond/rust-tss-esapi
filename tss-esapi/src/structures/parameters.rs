// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{KeyedHashScheme, SymmetricDefinitionObject},
    tss2_esys::{TPMS_KEYEDHASH_PARMS, TPMS_SYMCIPHER_PARMS},
    Error, Result,
};
use std::convert::{TryFrom, TryInto};

/// Keyed hash parameters
///
/// # Details
/// Corresponds to TPMS_KEYEDHASH_PARMS
#[derive(Clone, Copy, Debug)]
pub struct KeyedHashParameters {
    keyed_hash_scheme: KeyedHashScheme,
}

impl KeyedHashParameters {
    pub const fn new(keyed_hash_scheme: KeyedHashScheme) -> KeyedHashParameters {
        KeyedHashParameters { keyed_hash_scheme }
    }
}

impl TryFrom<TPMS_KEYEDHASH_PARMS> for KeyedHashParameters {
    type Error = Error;

    fn try_from(tpms_keyed_hash_parms: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        Ok(KeyedHashParameters {
            keyed_hash_scheme: tpms_keyed_hash_parms.scheme.try_into()?,
        })
    }
}

impl From<KeyedHashParameters> for TPMS_KEYEDHASH_PARMS {
    fn from(keyed_hash_prams: KeyedHashParameters) -> Self {
        TPMS_KEYEDHASH_PARMS {
            scheme: keyed_hash_prams.keyed_hash_scheme.into(),
        }
    }
}

/// Symmetric cipher parameters
///
/// # Details
/// Corresponds to TPMS_SYMCIPHER_PARMS
#[derive(Clone, Debug, Copy)]
pub struct SymmetricCipherParameters {
    symmetric_definition_object: SymmetricDefinitionObject,
}

impl SymmetricCipherParameters {
    /// Creates a new [SymmetricDefinitionObject]
    pub const fn new(
        symmetric_definition_object: SymmetricDefinitionObject,
    ) -> SymmetricCipherParameters {
        SymmetricCipherParameters {
            symmetric_definition_object,
        }
    }
}

impl TryFrom<TPMS_SYMCIPHER_PARMS> for SymmetricCipherParameters {
    type Error = Error;
    fn try_from(tpms_symcipher_params: TPMS_SYMCIPHER_PARMS) -> Result<SymmetricCipherParameters> {
        Ok(SymmetricCipherParameters {
            symmetric_definition_object: tpms_symcipher_params.sym.try_into()?,
        })
    }
}

impl From<SymmetricCipherParameters> for TPMS_SYMCIPHER_PARMS {
    fn from(symmetric_cipher_parameters: SymmetricCipherParameters) -> TPMS_SYMCIPHER_PARMS {
        TPMS_SYMCIPHER_PARMS {
            sym: symmetric_cipher_parameters
                .symmetric_definition_object
                .into(),
        }
    }
}
