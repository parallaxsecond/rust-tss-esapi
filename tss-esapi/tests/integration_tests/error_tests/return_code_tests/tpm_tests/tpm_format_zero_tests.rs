// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.

mod tpm_format_zero_error_tests;
mod tpm_format_zero_warning_tests;

use bitfield::bitfield;
use std::{convert::TryFrom, error::Error};
use tss_esapi::{
    constants::tss::{
        TPM2_RC_AUTHSIZE, TPM2_RC_CONTEXT_GAP, TPM2_RC_INITIALIZE, TSS2_TPM_RC_LAYER,
    },
    error::{
        ReturnCode, TpmFormatZeroErrorResponseCode, TpmFormatZeroResponseCode,
        TpmFormatZeroWarningResponseCode, TpmResponseCode,
    },
    tss2_esys::TSS2_RC,
};

bitfield! {
    pub struct VendorSpecificBitHelper(u32);
    _, set_is_vendor_specific: 10;
}

#[test]
fn test_vendor_specific_valid_conversions() {
    // Bit 10 In the TPM format zero return code is the bit indicating vendor specific.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = VendorSpecificBitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_is_vendor_specific(true);
    let expected_tss_rc = helper.0;

    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM zero error return code value with vendor specific bit set into a ReturnCode.");

    if let ReturnCode::Tpm(TpmResponseCode::FormatZero(
        TpmFormatZeroResponseCode::VendorSpecific(actual),
    )) = actual_rc
    {
        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual),
            "Converting vendor specific return code did not return the original value."
        );
    } else {
        panic!("TPM TSS2_RC layer did no convert into ReturnCode::Tpm");
    }

    assert_eq!(
        expected_tss_rc,
        TSS2_RC::from(actual_rc),
        "The vendor specific return code did not convert into the expected TSS2_RC in the TPM layer."
    )
}

#[test]
fn test_vendor_specific_error_trait_implementation() {
    // Bit 10 In the TPM format zero return code is the bit indicating vendor specific.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = VendorSpecificBitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_is_vendor_specific(true);
    let expected_tss_rc = helper.0;
    let expected_tss_rc_error_part = u16::try_from(expected_tss_rc)
        .expect("A TSS return code with the vendor specific bit set from the TPM layer should a valid u16 value.");
    let vendor_specific_rc = TpmFormatZeroResponseCode::VendorSpecific(expected_tss_rc_error_part);

    assert!(
        vendor_specific_rc.source().is_none(),
        "`source() method for vendor specific error did not return the expected value."
    );
}

#[test]
fn test_vendor_specific_display_trait_implementation() {
    // Bit 10 In the TPM format zero return code is the bit indicating vendor specific.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = VendorSpecificBitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_is_vendor_specific(true);
    let expected_tss_rc = helper.0;
    let expected_tss_rc_error_part = u16::try_from(expected_tss_rc)
        .expect("A TSS return code with the vendor specific bit set from the TPM layer should a valid u16 value.");
    let vendor_specific_rc = TpmFormatZeroResponseCode::VendorSpecific(expected_tss_rc_error_part);

    assert_eq!(
        "Vendor specific error.",
        format!("{}", vendor_specific_rc),
        "The vendor specific return code did not produce the expected error message."
    );
}

bitfield! {
    pub struct ErrorNumberHelper(u32);
    u8, error_number, _: 6, 0;
}

macro_rules! test_display_trait_impl {
    ($source_rc:ident, $tss_rc:ident) => {
        let value = u16::try_from(TSS2_TPM_RC_LAYER | $tss_rc)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the valid TSS2 response code {} from the TPM layer into a u16 value.",
                    std::stringify!($tss_rc));
            });

        let response_code =  TpmFormatZeroResponseCode::try_from(value)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a u16 value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                    std::stringify!($tss_rc),
                    std::any::type_name::<TpmFormatZeroResponseCode>());
            });

        let helper = ErrorNumberHelper(TSS2_TPM_RC_LAYER | $tss_rc);

        let source_response_code = $source_rc::try_from(helper.error_number())
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the bits 0-6 a value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                    std::stringify!($tss_rc),
                    std::any::type_name::<$source_rc>());
            });

        assert_eq!(
            format!("{}", response_code),
            format!("{}", source_response_code)
        );
    };
}

#[test]
fn test_error_display_implementation() {
    test_display_trait_impl!(TpmFormatZeroWarningResponseCode, TPM2_RC_CONTEXT_GAP);
    test_display_trait_impl!(TpmFormatZeroErrorResponseCode, TPM2_RC_AUTHSIZE);
}

macro_rules! test_error_trait_impl {
    ($source_rc:ident, $tss_rc:ident) => {
        let value = u16::try_from(TSS2_TPM_RC_LAYER | $tss_rc)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the valid TSS2 response code {} from the TPM layer into a u16 value.",
                    std::stringify!($tss_rc));
            });

        let response_code =  TpmFormatZeroResponseCode::try_from(value)
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert a u16 value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                    std::stringify!($tss_rc),
                    std::any::type_name::<TpmFormatZeroResponseCode>());
            });

        let helper = ErrorNumberHelper(TSS2_TPM_RC_LAYER | $tss_rc);

        let actual_source_rc = response_code.source()
            .unwrap_or_else(|| {
                    panic!(
                        "The `{}` object produced from the valid TSS2 response code {} from the TPM layer should have a source.",
                        std::any::type_name::<TpmFormatZeroResponseCode>(),
                        std::stringify!($tss_rc));
            });

        let expected_source_rc = $source_rc::try_from(helper.error_number())
            .unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert the bits 0-6 a value representing a valid TSS2 response code {} from the TPM layer into a `{}` object.",
                    std::stringify!($tss_rc),
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
    test_error_trait_impl!(TpmFormatZeroWarningResponseCode, TPM2_RC_CONTEXT_GAP);
    test_error_trait_impl!(TpmFormatZeroErrorResponseCode, TPM2_RC_AUTHSIZE);
}
