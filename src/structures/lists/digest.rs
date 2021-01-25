// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::structures::Digest;
use crate::tss2_esys::TPML_DIGEST;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::TryFrom;

#[derive(Debug, Clone, Default)]
pub struct DigestList {
    digests: Vec<Digest>,
}

impl DigestList {
    // minimum is two for TPM2_PolicyOR().
    pub const MIN_SIZE: usize = 2;
    pub const MAX_SIZE: usize = 8;
    pub fn new() -> Self {
        DigestList {
            digests: Vec::new(),
        }
    }

    pub fn value(&self) -> &[Digest] {
        &self.digests
    }

    pub fn add(&mut self, dig: Digest) -> Result<()> {
        if self.digests.len() >= DigestList::MAX_SIZE {
            error!("Error: Exceeded maximum count(> {})", DigestList::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        self.digests.push(dig);
        Ok(())
    }
}

impl TryFrom<TPML_DIGEST> for DigestList {
    type Error = Error;
    fn try_from(tpml_digest: TPML_DIGEST) -> Result<Self> {
        let digests_count = tpml_digest.count as usize;
        if digests_count < DigestList::MIN_SIZE {
            error!(
                "Error: Invalid TPML_DIGEST count(< {})",
                DigestList::MIN_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        if digests_count > DigestList::MAX_SIZE {
            error!(
                "Error: Invalid TPML_DIGEST count(> {})",
                DigestList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        let digests = &tpml_digest.digests[..digests_count];
        let digests: Result<Vec<Digest>> = digests.iter().map(|x| Digest::try_from(*x)).collect();
        Ok(DigestList { digests: digests? })
    }
}

impl TryFrom<DigestList> for TPML_DIGEST {
    type Error = Error;
    fn try_from(digest_list: DigestList) -> Result<Self> {
        if digest_list.digests.len() < DigestList::MIN_SIZE {
            error!(
                "Error: Invalid digest list size(< {})",
                DigestList::MIN_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        if digest_list.digests.len() > DigestList::MAX_SIZE {
            error!(
                "Error: Invalid digest list size(> {})",
                DigestList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }

        let mut tss_digest_list: TPML_DIGEST = Default::default();
        for digest in digest_list.digests.iter() {
            tss_digest_list.digests[tss_digest_list.count as usize] = digest.clone().into();
            tss_digest_list.count += 1;
        }
        Ok(tss_digest_list)
    }
}
