// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::algorithm::HashingAlgorithm;
use crate::structures::Digest;
use crate::tss2_esys::{TPMT_HA, TPMU_HA};
use crate::{Error, Result, WrapperErrorKind};
use std::convert::{TryFrom, TryInto};

impl TryFrom<(HashingAlgorithm, Digest)> for TPMT_HA {
    type Error = Error;
    fn try_from(digest: (HashingAlgorithm, Digest)) -> Result<Self> {
        let algid: crate::tss2_esys::TPM2_ALG_ID = digest.0.into();
        let digest_val = digest.1;
        Ok(TPMT_HA {
            hashAlg: algid,
            digest: match digest.0 {
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
