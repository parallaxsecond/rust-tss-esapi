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
///
/// # Example
///
/// ```rust
/// use std::convert::{TryFrom, TryInto};
/// use tss_esapi::{
///     structures::{Digest, Name, NvDigestCertifyInfo},
///     tss2_esys::TPMS_NV_DIGEST_CERTIFY_INFO,
/// };
///
/// let index_name = Name::try_from(vec![0xAA; 34])?;
/// let nv_digest = Digest::try_from(vec![0xBB; 32])?;
/// let info: NvDigestCertifyInfo = TPMS_NV_DIGEST_CERTIFY_INFO {
///     indexName: index_name.clone().into(),
///     nvDigest: nv_digest.clone().into(),
/// }
/// .try_into()?;
///
/// assert_eq!(info.index_name(), &index_name);
/// assert_eq!(info.nv_digest(), &nv_digest);
/// # Ok::<(), tss_esapi::Error>(())
/// ```
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
        Ok(Self {
            index_name: tpms_nv_digest_certify_info.indexName.try_into()?,
            nv_digest: tpms_nv_digest_certify_info.nvDigest.try_into()?,
        })
    }
}
