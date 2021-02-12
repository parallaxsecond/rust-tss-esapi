// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::interface_types::algorithm::HashingAlgorithm;
use crate::structures::Digest;
use crate::tss2_esys::{TPMT_HA, TPMU_HA};
use crate::{Error, Result, WrapperErrorKind};
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub struct HashAgile {
    algorithm: HashingAlgorithm,
    digest: Digest,
}

impl HashAgile {
    pub fn new(algorithm: HashingAlgorithm, digest: Digest) -> Self {
        HashAgile { algorithm, digest }
    }
}

impl TryFrom<HashAgile> for TPMT_HA {
    type Error = Error;
    fn try_from(ha: HashAgile) -> Result<Self> {
        let algid: crate::tss2_esys::TPM2_ALG_ID = ha.algorithm.into();
        let digest_val = ha.digest;
        Ok(TPMT_HA {
            hashAlg: algid,
            digest: match ha.algorithm {
                HashingAlgorithm::Sha1 => TPMU_HA {
                    sha1: digest_val.try_into()?,
                },
                HashingAlgorithm::Sha256 => TPMU_HA {
                    sha256: digest_val.try_into()?,
                },
                HashingAlgorithm::Sha384 => TPMU_HA {
                    sha384: digest_val.try_into()?,
                },
                HashingAlgorithm::Sha512 => TPMU_HA {
                    sha512: digest_val.try_into()?,
                },
                HashingAlgorithm::Sm3_256 => TPMU_HA {
                    sm3_256: digest_val.try_into()?,
                },
                _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            },
        })
    }
}
