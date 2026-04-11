// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result,
    structures::{Digest, Name},
    tss2_esys::TPMS_NV_DIGEST_CERTIFY_INFO,
};
use std::convert::{TryFrom, TryInto};

/// This structure contains the Name and hash of the
/// contents of the selected NV Index that is certified by
/// TPM2_NV_Certify()
///
/// # Details
/// This corresponds to  TPMS_NV_DIGEST_CERTIFY_INFO.
#[derive(Debug, Clone)]
pub struct NvDigestCertifyInfo {
    index_name: Name,
    nv_digest: Digest,
}

impl NvDigestCertifyInfo {
    /// Returns the index name
    pub const fn index_name(&self) -> &Name {
        &self.index_name
    }

    /// Returns the NV digest.
    pub const fn nv_digest(&self) -> &Digest {
        &self.nv_digest
    }
}

impl From<NvDigestCertifyInfo> for TPMS_NV_DIGEST_CERTIFY_INFO {
    fn from(nv_digest_certify_info: NvDigestCertifyInfo) -> Self {
        TPMS_NV_DIGEST_CERTIFY_INFO {
            indexName: nv_digest_certify_info.index_name.into(),
            nvDigest: nv_digest_certify_info.nv_digest.into(),
        }
    }
}

impl TryFrom<TPMS_NV_DIGEST_CERTIFY_INFO> for NvDigestCertifyInfo {
    type Error = Error;

    fn try_from(tpms_nv_digest_certify_info: TPMS_NV_DIGEST_CERTIFY_INFO) -> Result<Self> {
        Ok(NvDigestCertifyInfo {
            index_name: tpms_nv_digest_certify_info.indexName.try_into()?,
            nv_digest: tpms_nv_digest_certify_info.nvDigest.try_into()?,
        })
    }
}
