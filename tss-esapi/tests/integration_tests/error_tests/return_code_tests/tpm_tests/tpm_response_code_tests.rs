// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_RC_ASYMMETRIC, TPM2_RC_SEQUENCE, TSS2_TPM_RC_LAYER},
    error::{ReturnCode, TpmResponseCode},
};

#[test]
fn test_valid_tpm_format_zero_response_code() {
    let expected_tss_rc = TSS2_TPM_RC_LAYER | TPM2_RC_SEQUENCE;
    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM2_RC_SEQUENCE in the TPM layer to a ReturnCode.");

    if let ReturnCode::Tpm(actual_tpm_response_code) = actual_rc {
        match actual_tpm_response_code {
            TpmResponseCode::FormatZero(_) => {}
            _ => {
                panic!("TPM2_RC_SEQUENCE in the TPM layer did not convert into the expected TpmResponseCode");
            }
        }
    } else {
        panic!("The TPM layer did not convert into the expected ReturnCode");
    }

    assert_eq!(
        expected_tss_rc,
        actual_rc.into(),
        "ReturnCode::Tpm did not convert into the expected TSS2_RC value"
    );
}

#[test]
fn test_valid_tpm_format_one_response_code() {
    let expected_tss_rc = TSS2_TPM_RC_LAYER | TPM2_RC_ASYMMETRIC;
    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM2_RC_ASYMMETRIC in the TPM layer to a ReturnCode.");

    if let ReturnCode::Tpm(actual_tpm_response_code) = actual_rc {
        match actual_tpm_response_code {
            TpmResponseCode::FormatOne(_) => {}
            _ => {
                panic!("TPM2_RC_ASYMMETRIC in the TPM layer did not convert into the expected TpmResponseCode");
            }
        }
    } else {
        panic!("The TPM layer did not convert into the expected ReturnCode");
    }

    assert_eq!(
        expected_tss_rc,
        actual_rc.into(),
        "ReturnCode::Tpm did not convert into the expected TSS2_RC value"
    );
}
