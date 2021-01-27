// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::algorithm::{HashingAlgorithm, KeyDerivationFunction},
    constants::tss::*,
    tss2_esys::*,
    Error, Result, WrapperErrorKind,
};
use std::convert::{TryFrom, TryInto};

#[derive(Clone, Copy, Debug)]
pub enum KeyedHashParms {
    XOR {
        hash_alg: HashingAlgorithm,
        kdf: KeyDerivationFunction,
    },
    HMAC {
        hash_alg: HashingAlgorithm,
    },
}

impl TryFrom<TPMS_KEYEDHASH_PARMS> for KeyedHashParms {
    type Error = Error;

    fn try_from(parms: TPMS_KEYEDHASH_PARMS) -> Result<Self> {
        match parms.scheme.scheme {
            TPM2_ALG_HMAC => Ok(KeyedHashParms::HMAC {
                hash_alg: unsafe { parms.scheme.details.hmac.hashAlg }.try_into()?,
            }),
            TPM2_ALG_XOR => Ok(KeyedHashParms::XOR {
                hash_alg: unsafe { parms.scheme.details.exclusiveOr.hashAlg }.try_into()?,
                kdf: unsafe { parms.scheme.details.exclusiveOr.kdf }.try_into()?,
            }),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

impl TryFrom<KeyedHashParms> for TPMS_KEYEDHASH_PARMS {
    type Error = Error;

    fn try_from(parms: KeyedHashParms) -> Result<Self> {
        match parms {
            KeyedHashParms::HMAC { hash_alg } => Ok(TPMS_KEYEDHASH_PARMS {
                scheme: TPMT_KEYEDHASH_SCHEME {
                    scheme: TPM2_ALG_HMAC,
                    details: TPMU_SCHEME_KEYEDHASH {
                        hmac: TPMS_SCHEME_HMAC {
                            hashAlg: hash_alg.into(),
                        },
                    },
                },
            }),
            KeyedHashParms::XOR { hash_alg, kdf } => Ok(TPMS_KEYEDHASH_PARMS {
                scheme: TPMT_KEYEDHASH_SCHEME {
                    scheme: TPM2_ALG_XOR,
                    details: TPMU_SCHEME_KEYEDHASH {
                        exclusiveOr: TPMS_SCHEME_XOR {
                            hashAlg: hash_alg.into(),
                            kdf: kdf.into(),
                        },
                    },
                },
            }),
        }
    }
}
