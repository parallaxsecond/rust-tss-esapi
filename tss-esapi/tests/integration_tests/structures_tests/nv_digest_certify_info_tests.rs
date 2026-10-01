// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    structures::{Digest, Name, NvDigestCertifyInfo},
    tss2_esys::TPMS_NV_DIGEST_CERTIFY_INFO,
};

#[test]
fn test_conversion() {
    let expected_index_name =
        Name::try_from(vec![0xf0u8; 34]).expect("Failed to create index name");
    let expected_nv_digest =
        Digest::try_from(vec![0xfcu8; 32]).expect("Failed to create NV digest");
    let expected_tpms_nv_digest_certify_info = TPMS_NV_DIGEST_CERTIFY_INFO {
        indexName: expected_index_name.clone().into(),
        nvDigest: expected_nv_digest.clone().into(),
    };

    let nv_digest_certify_info: NvDigestCertifyInfo = expected_tpms_nv_digest_certify_info
        .try_into()
        .expect("Failed to convert TPMS_NV_DIGEST_CERTIFY_INFO into NvDigestCertifyInfo");
    assert_eq!(
        &expected_index_name,
        nv_digest_certify_info.index_name(),
        "NvDigestCertifyInfo did not contain the expected index name",
    );
    assert_eq!(
        &expected_nv_digest,
        nv_digest_certify_info.nv_digest(),
        "NvDigestCertifyInfo did not contain the expected NV digest",
    );

    let actual_tpms_nv_digest_certify_info: TPMS_NV_DIGEST_CERTIFY_INFO =
        nv_digest_certify_info.into();

    crate::common::ensure_tpms_nv_digest_certify_info_equality(
        &expected_tpms_nv_digest_certify_info,
        &actual_tpms_nv_digest_certify_info,
    );
}
