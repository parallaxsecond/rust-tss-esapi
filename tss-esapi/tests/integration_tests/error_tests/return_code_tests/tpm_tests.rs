// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod tpm_format_one_argument_number_tests;
mod tpm_format_one_error_tests;
mod tpm_format_zero_tests;

use std::{convert::TryFrom, error::Error};
use tss_esapi::{
    constants::tss::{TPM2_RC_ASYMMETRIC, TPM2_RC_SEQUENCE, TSS2_TPM_RC_LAYER},
    error::{ReturnCode, TpmFormatOneResponseCode, TpmFormatZeroResponseCode, TpmResponseCode},
};

macro_rules! test_valid_conversions {
    (TpmResponseCode::$tpm_rc_item:ident, $tss_rc:ident) => {
        let expected_tss_rc = TSS2_TPM_RC_LAYER | $tss_rc;
        let actual_rc = ReturnCode::try_from(expected_tss_rc).unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} in the TPM layer to a {}.",
                std::stringify!($tss_rc),
                std::any::type_name::<ReturnCode>()
            )
        });

        if let ReturnCode::Tpm(actual_tpm_response_code) = actual_rc {
            match actual_tpm_response_code {
                TpmResponseCode::$tpm_rc_item(_) => {}
                _ => {
                    panic!(
                        "{} in the TPM layer did not convert into the expected {}.",
                        std::stringify!($tss_rc),
                        std::any::type_name::<TpmResponseCode>()
                    );
                }
            }
        } else {
            panic!(
                "The TPM layer did not convert into the expected {}.",
                std::any::type_name::<ReturnCode>()
            );
        }

        assert_eq!(
            expected_tss_rc,
            actual_rc.into(),
            "ReturnCode::Tpm did not convert into the expected TSS2_RC value."
        );
    };
}

#[test]
fn test_valid_tpm_format_zero_response_code() {
    test_valid_conversions!(TpmResponseCode::FormatZero, TPM2_RC_SEQUENCE);
}

#[test]
fn test_valid_tpm_format_one_response_code() {
    test_valid_conversions!(TpmResponseCode::FormatOne, TPM2_RC_ASYMMETRIC);
}

macro_rules! test_display_trait_impl {
    ($source_rc:ident, $tss_rc:ident) => {
        let value = u16::try_from(TSS2_TPM_RC_LAYER | $tss_rc)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the valid TSS2 response code {} from the TPM layer into a u16 value.",
                    std::stringify!($tss_rc));
            });

        let response_code =  TpmResponseCode::try_from(value)
        .unwrap_or_else(|_| {
            panic!(
                "It should be possible to convert a u16 value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                std::stringify!($tss_rc),
                std::any::type_name::<TpmResponseCode>());
        });


        let source_response_code = $source_rc::try_from(value)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a u16 value representing a valid TSS2 response code from the TPM layer into a `{}` object.",
                    std::any::type_name::<$source_rc>());
            });

        assert_eq!(
            format!("{}", response_code),
            format!("{}", source_response_code)
        );
    };
}

#[test]
fn test_display_trait_implementation() {
    test_display_trait_impl!(TpmFormatZeroResponseCode, TPM2_RC_SEQUENCE);
    test_display_trait_impl!(TpmFormatOneResponseCode, TPM2_RC_ASYMMETRIC);
}

macro_rules! test_error_trait_impl {
    ($source_rc:ident, $tss_rc:ident) => {
        let value = u16::try_from(TSS2_TPM_RC_LAYER | $tss_rc)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the valid TSS2 response code {} from the TPM layer into a u16 value.",
                    std::stringify!($tss_rc));
            });

        let response_code =  TpmResponseCode::try_from(value)
        .unwrap_or_else(|_| {
            panic!(
                "It should be possible to convert a u16 value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                std::stringify!($tss_rc),
                std::any::type_name::<TpmResponseCode>());
        });

        let actual_source_rc = response_code.source()
            .unwrap_or_else(|| {
                    panic!(
                        "The `{}` object produced from the valid TSS2 response code {} from the TPM layer should have a source.",
                        std::any::type_name::<TpmResponseCode>(),
                        std::stringify!($tss_rc));
            });

        let expected_source_rc = $source_rc::try_from(value)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a u16 value representing a valid TSS2 response code from the TPM layer into a `{}` object.",
                    std::any::type_name::<$source_rc>());
            });

            assert_eq!(
                format!("{}", actual_source_rc),
                format!("{}", expected_source_rc)
            );
    };
}

#[test]
fn test_error_trait_implementation() {
    test_error_trait_impl!(TpmFormatZeroResponseCode, TPM2_RC_SEQUENCE);
    test_error_trait_impl!(TpmFormatOneResponseCode, TPM2_RC_ASYMMETRIC);
}
