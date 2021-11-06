// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    structures::{CertifyInfo, Name},
    tss2_esys::TPMS_CERTIFY_INFO,
};

#[test]
fn test_conversion() {
    let expected_name = Name::try_from(vec![0xffu8; 64]).expect("Failed to create name");
    let expected_qualified_name =
        Name::try_from(vec![0x0fu8; 64]).expect("Failed to create qualified name");
    let expected_tpms_certify_info = TPMS_CERTIFY_INFO {
        name: expected_name
            .clone()
            .try_into()
            .expect("Failed to convert name to tss type"),
        qualifiedName: expected_qualified_name
            .clone()
            .try_into()
            .expect("failed to convert qualified name to tss type"),
    };

    let certify_info = CertifyInfo::try_from(expected_tpms_certify_info)
        .expect("Failed to convert TPMS_CERTIFY_INFO to certifyInfo");
    assert_eq!(
        &expected_name,
        certify_info.name(),
        "Converted certify info did not contain expected name"
    );
    assert_eq!(
        &expected_qualified_name,
        certify_info.qualified_name(),
        "Converted certify info did not contain expected qualified name"
    );

    let actual_tpms_certify_info: TPMS_CERTIFY_INFO = certify_info.into();

    crate::common::ensure_tpms_certify_info_equality(
        &expected_tpms_certify_info,
        &actual_tpms_certify_info,
    );
}
