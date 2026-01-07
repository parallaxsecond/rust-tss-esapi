// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_RC_ASYMMETRIC, TPM2_RC_SEQUENCE, TSS2_RESMGR_TPM_RC_LAYER},
    error::{ReturnCode, TpmResponseCode},
    tss2_esys::TSS2_RC,
};

// no interaction with swtpm, can be parallel
#[test]
fn test_valid_tpm_resmgr_format_zero_response_code() {
    let expected_tss_rc = TSS2_RESMGR_TPM_RC_LAYER | TPM2_RC_SEQUENCE;
    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM2_RC_SEQUENCE in the TPM RESMGR layer to a ReturnCode.");

    if let ReturnCode::TpmResourceManager(actual_tpm_response_code) = actual_rc {
        assert!(
            matches!(actual_tpm_response_code,TpmResponseCode::FormatZero(_)),
            "TPM2_RC_SEQUENCE in the TPM RESMGR layer did not convert into the expected TpmResponseCode"
        );
    } else {
        panic!("The TPM RESMGR layer did not convert into the expected ReturnCode");
    }

    assert_eq!(
        expected_tss_rc,
        TSS2_RC::from(actual_rc),
        "ReturnCode::TpmResourceManager did not convert into the expected TSS2_RC value"
    );
}

#[test]
fn test_valid_tpm_resmgr_format_one_response_code() {
    let expected_tss_rc = TSS2_RESMGR_TPM_RC_LAYER | TPM2_RC_ASYMMETRIC;
    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM2_RC_ASYMMETRIC in the TPM RESMGR layer to a ReturnCode.");

    if let ReturnCode::TpmResourceManager(actual_tpm_response_code) = actual_rc {
        assert!(
            matches!(actual_tpm_response_code, TpmResponseCode::FormatOne(_)),
            "TPM2_RC_ASYMMETRIC in the TPM RESMGR layer did not convert into the expected TpmResponseCode"
        );
    } else {
        panic!("The TPM RESMGR layer did not convert into the expected ReturnCode");
    }

    assert_eq!(
        expected_tss_rc,
        TSS2_RC::from(actual_rc),
        "ReturnCode::TpmResourceManager did not convert into the expected TSS2_RC value"
    );
}
