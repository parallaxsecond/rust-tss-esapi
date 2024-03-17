// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::tss2_esys::{
    TPM2B_AUTH, TPM2B_CONTEXT_DATA, TPM2B_DATA, TPM2B_DIGEST, TPM2B_MAX_NV_BUFFER, TPM2B_NAME,
    TPM2B_SENSITIVE_CREATE, TPM2B_SENSITIVE_DATA,
};

macro_rules! ensure_sized_buffer_equality {
    ($expected:ident, $actual:ident, $buffer_field_name:ident, $tss_type:ident) => {
        assert_eq!(
            $expected.size,
            $actual.size,
            "'size' value in {}, mismatch between actual and expected",
            stringify!($tss_type),
        );
        assert_eq!(
            $expected.$buffer_field_name,
            $actual.$buffer_field_name,
            "'{}' value in {}, mismatch between actual and expected",
            stringify!($buffer_field_name),
            stringify!($tss_type),
        );
    };
}

pub fn ensure_tpm2b_name_equality(expected: &TPM2B_NAME, actual: &TPM2B_NAME) {
    ensure_sized_buffer_equality!(expected, actual, name, TPM2B_NAME);
}

pub fn ensure_tpm2b_digest_equality(expected: &TPM2B_DIGEST, actual: &TPM2B_DIGEST) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_DIGEST);
}

pub fn ensure_tpm2b_data_equality(expected: &TPM2B_DATA, actual: &TPM2B_DATA) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_DATA);
}

pub fn ensure_tpm2b_auth_equality(expected: &TPM2B_AUTH, actual: &TPM2B_AUTH) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_AUTH);
}

pub fn ensure_tpm2b_sensitive_data(expected: &TPM2B_SENSITIVE_DATA, actual: &TPM2B_SENSITIVE_DATA) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_SENSITIVE_DATA);
}

pub fn ensure_tpm2b_max_nv_buffer_equality(
    expected: &TPM2B_MAX_NV_BUFFER,
    actual: &TPM2B_MAX_NV_BUFFER,
) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_MAX_NV_BUFFER);
}

pub fn ensure_tpm2b_sensitive_create_equality(
    expected: &TPM2B_SENSITIVE_CREATE,
    actual: &TPM2B_SENSITIVE_CREATE,
) {
    assert_eq!(
        expected.size, actual.size,
        "'size' value in TPM2B_SENSITIVE_CREATE, mismatch between actual and expected",
    );
    crate::common::ensure_tpms_sensitive_create_equality(&expected.sensitive, &actual.sensitive);
}

pub fn ensure_tpm2b_context_data_equality(
    expected: &TPM2B_CONTEXT_DATA,
    actual: &TPM2B_CONTEXT_DATA,
) {
    ensure_sized_buffer_equality!(expected, actual, buffer, TPM2B_CONTEXT_DATA);
}
