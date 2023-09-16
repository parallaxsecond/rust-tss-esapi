// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    structures::{Auth, SensitiveCreate, SensitiveData},
    tss2_esys::{TPM2B_SENSITIVE_CREATE, TPMS_SENSITIVE_CREATE},
};

#[test]
fn test_apis() {
    let expected_auth =
        Auth::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("Failed to create Auth value");
    let expect_sensitive_data =
        SensitiveData::try_from(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .expect("Failed to create sensitive data");
    let sensitive_create =
        SensitiveCreate::new(expected_auth.clone(), expect_sensitive_data.clone());
    assert_eq!(
        &expected_auth,
        sensitive_create.user_auth(),
        "user_auth() did not return expected value"
    );
    assert_eq!(
        &expect_sensitive_data,
        sensitive_create.data(),
        "data() did not return expected value"
    );
}

#[test]
fn test_tpms_sensitive_create_conversions() {
    let expected_auth =
        Auth::try_from(vec![1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("Failed to create Auth value");
    let expect_sensitive_data =
        SensitiveData::try_from(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .expect("Failed to create sensitive data");
    let expected_tpms_sensitive_create = TPMS_SENSITIVE_CREATE {
        userAuth: expected_auth.clone().into(),
        data: expect_sensitive_data.clone().into(),
    };
    let sensitive_create = SensitiveCreate::try_from(expected_tpms_sensitive_create)
        .expect("Failed to convert TPMS_SENSITIVE_CREATE to SensitiveCreate");
    assert_eq!(
        &expected_auth,
        sensitive_create.user_auth(),
        "user_auth() did not return expected value"
    );
    assert_eq!(
        &expect_sensitive_data,
        sensitive_create.data(),
        "data() did not return expected value"
    );
    let actual_tpms_sensitive_create: TPMS_SENSITIVE_CREATE = sensitive_create.into();
    crate::common::ensure_tpms_sensitive_create_equality(
        &expected_tpms_sensitive_create,
        &actual_tpms_sensitive_create,
    );
}

#[test]
fn test_tpm2b_senestive_create_conversions() {
    let expected_auth =
        Auth::try_from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("Failed to create Auth value");
    let expect_sensitive_data =
        SensitiveData::try_from(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .expect("Failed to create sensitive data");
    let expected_sensitive_create =
        SensitiveCreate::new(expected_auth.clone(), expect_sensitive_data.clone());
    let expected_tpm2b_sensitive_create = TPM2B_SENSITIVE_CREATE {
        size: 2 + expected_auth.len() as u16 + 2 + expect_sensitive_data.len() as u16,
        sensitive: expected_sensitive_create.clone().into(),
    };
    let actual_sensitive_create = SensitiveCreate::try_from(expected_tpm2b_sensitive_create)
        .expect("Failed to convert TPM2B_SENSITIVE_CREATE into SensitiveCreate");
    assert_eq!(expected_sensitive_create, actual_sensitive_create, "The SensitiveCreate converted from the TPM2b_SENSITIVE_CREATE did not contain the expected values");
    let actual_tpm2b_sensitive_create = TPM2B_SENSITIVE_CREATE::try_from(actual_sensitive_create)
        .expect("Failed to create TPM2b_SENSITIVE_CREATE from SensitiveCreate");
    crate::common::ensure_tpm2b_sensitive_create_equality(
        &expected_tpm2b_sensitive_create,
        &actual_tpm2b_sensitive_create,
    );
}

#[test]
fn test_marhsall_unmarshall() {
    let sensitive_create = SensitiveCreate::new(
        Auth::try_from(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).expect("Failed to create Auth value"),
        SensitiveData::try_from(vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19])
            .expect("Failed to create sensitive data"),
    );
    crate::common::check_marshall_unmarshall(&sensitive_create);
}
