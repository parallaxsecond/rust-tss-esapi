// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    constants::tss::{TPM2_ALG_AES, TPM2_ALG_CAMELLIA, TPM2_ALG_NULL, TPM2_ALG_SM4, TPM2_ALG_XOR},
    tss2_esys::TPMT_SYM_DEF,
};

pub fn ensure_tpmt_sym_def_equality(expected: &TPMT_SYM_DEF, actual: &TPMT_SYM_DEF) {
    assert_eq!(
        expected.algorithm, actual.algorithm,
        "'algorithm' value in TPMT_SYM_DEF, mismatch between actual and expected",
    );

    match expected.algorithm {
        TPM2_ALG_AES => {
            let expected_key_bits = unsafe { expected.keyBits.aes };
            let expected_mode = unsafe { expected.mode.aes };
            let actual_key_bits = unsafe { actual.keyBits.aes };
            let actual_mode = unsafe { actual.mode.aes };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_SM4 => {
            let expected_key_bits = unsafe { expected.keyBits.sm4 };
            let expected_mode = unsafe { expected.mode.sm4 };
            let actual_key_bits = unsafe { actual.keyBits.sm4 };
            let actual_mode = unsafe { actual.mode.sm4 };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_CAMELLIA => {
            let expected_key_bits = unsafe { expected.keyBits.camellia };
            let expected_mode = unsafe { expected.mode.camellia };
            let actual_key_bits = unsafe { actual.keyBits.camellia };
            let actual_mode = unsafe { actual.mode.camellia };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );

            assert_eq!(
                expected_mode, actual_mode,
                "'mode' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_XOR => {
            let expected_key_bits = unsafe { expected.keyBits.exclusiveOr };
            let actual_key_bits = unsafe { actual.keyBits.exclusiveOr };
            assert_eq!(
                expected_key_bits, actual_key_bits,
                "'keyBits' value in TPMT_SYM_DEF, mismatch between actual and expected",
            );
        }
        TPM2_ALG_NULL => {}
        _ => {
            panic!("Invalid algorithm in TPMT_SYM_DEF");
        }
    }
}
