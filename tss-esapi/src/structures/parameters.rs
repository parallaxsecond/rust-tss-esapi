// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::tagged::schemes::KeyedHashScheme, tss2_esys::TPMS_KEYEDHASH_PARMS, Error, Result,
};
use std::convert::{TryFrom, TryInto};

#[derive(Clone, Copy, Debug)]
pub struct KeyedHashParms {
    keyed_hash_scheme: KeyedHashScheme,
}

impl KeyedHashParms {
    pub const fn new(keyed_hash_scheme: KeyedHashScheme) -> KeyedHashParms {
        KeyedHashParms { keyed_hash_scheme }
    }
}

impl TryFrom<TPMS_KEYEDHASH_PARMS> for KeyedHashParms {
    type Error = Error;

    fn try_from(tpms_keyed_hash_parms: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        Ok(KeyedHashParms {
            keyed_hash_scheme: tpms_keyed_hash_parms.scheme.try_into()?,
        })
    }
}

impl From<KeyedHashParms> for TPMS_KEYEDHASH_PARMS {
    fn from(keyed_hash_prams: KeyedHashParms) -> Self {
        TPMS_KEYEDHASH_PARMS {
            scheme: keyed_hash_prams.keyed_hash_scheme.into(),
        }
    }
}
