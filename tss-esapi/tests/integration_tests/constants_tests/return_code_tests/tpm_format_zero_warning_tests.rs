// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use serial_test::serial;
use bitfield::bitfield;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatZeroWarning,
        tss::{
            TPM2_RC_CANCELED, TPM2_RC_CONTEXT_GAP, TPM2_RC_LOCALITY, TPM2_RC_LOCKOUT,
            TPM2_RC_MEMORY, TPM2_RC_NV_RATE, TPM2_RC_NV_UNAVAILABLE, TPM2_RC_OBJECT_HANDLES,
            TPM2_RC_OBJECT_MEMORY, TPM2_RC_REFERENCE_H0, TPM2_RC_REFERENCE_H1,
            TPM2_RC_REFERENCE_H2, TPM2_RC_REFERENCE_H3, TPM2_RC_REFERENCE_H4, TPM2_RC_REFERENCE_H5,
            TPM2_RC_REFERENCE_H6, TPM2_RC_REFERENCE_S0, TPM2_RC_REFERENCE_S1, TPM2_RC_REFERENCE_S2,
            TPM2_RC_REFERENCE_S3, TPM2_RC_REFERENCE_S4, TPM2_RC_REFERENCE_S5, TPM2_RC_REFERENCE_S6,
            TPM2_RC_RETRY, TPM2_RC_SESSION_HANDLES, TPM2_RC_SESSION_MEMORY, TPM2_RC_TESTING,
            TPM2_RC_YIELDED,
        },
    },
    Error, WrapperErrorKind,
};

bitfield! {
    #[derive(PartialEq, Copy, Clone)]
    struct TpmFormatZeroWarningRc(u16);
    u8, error_number, set_error_number: 6, 0;
}

macro_rules! test_valid_conversion {
    ($tpm_warn_rc:ident, $item:ident) => {
        let tpm_rc = TpmFormatZeroWarningRc($tpm_warn_rc as u16);
        assert_eq!(
            tpm_rc.error_number(),
            u8::from(TpmFormatZeroWarning::$item),
            "Conversion of {} into a u16 value without TPM2_RC_VER1 did not produce the expected value {}",
            std::stringify!(TpmFormatZeroWarning::$item),
            tpm_rc.error_number()
        );
        assert_eq!(
            TpmFormatZeroWarning::$item,
            TpmFormatZeroWarning::try_from(tpm_rc.error_number())
                .expect(&format!("Failed to convert the u16 value {} into TpmFormatZeroWarning", tpm_rc.error_number())),
            "Conversion of {} into TpmFormatZeroWarning did not produce the expected {}",
            tpm_rc.error_number(),
            std::stringify!(TpmFormatZeroWarning::$item)
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_RC_CONTEXT_GAP, ContextGap);
    test_valid_conversion!(TPM2_RC_OBJECT_MEMORY, ObjectMemory);
    test_valid_conversion!(TPM2_RC_SESSION_MEMORY, SessionMemory);
    test_valid_conversion!(TPM2_RC_MEMORY, Memory);
    test_valid_conversion!(TPM2_RC_SESSION_HANDLES, SessionHandles);
    test_valid_conversion!(TPM2_RC_OBJECT_HANDLES, ObjectHandles);
    test_valid_conversion!(TPM2_RC_LOCALITY, Locality);
    test_valid_conversion!(TPM2_RC_YIELDED, Yielded);
    test_valid_conversion!(TPM2_RC_CANCELED, Canceled);
    test_valid_conversion!(TPM2_RC_TESTING, Testing);
    test_valid_conversion!(TPM2_RC_REFERENCE_H0, ReferenceH0);
    test_valid_conversion!(TPM2_RC_REFERENCE_H1, ReferenceH1);
    test_valid_conversion!(TPM2_RC_REFERENCE_H2, ReferenceH2);
    test_valid_conversion!(TPM2_RC_REFERENCE_H3, ReferenceH3);
    test_valid_conversion!(TPM2_RC_REFERENCE_H4, ReferenceH4);
    test_valid_conversion!(TPM2_RC_REFERENCE_H5, ReferenceH5);
    test_valid_conversion!(TPM2_RC_REFERENCE_H6, ReferenceH6);
    test_valid_conversion!(TPM2_RC_REFERENCE_S0, ReferenceS0);
    test_valid_conversion!(TPM2_RC_REFERENCE_S1, ReferenceS1);
    test_valid_conversion!(TPM2_RC_REFERENCE_S2, ReferenceS2);
    test_valid_conversion!(TPM2_RC_REFERENCE_S3, ReferenceS3);
    test_valid_conversion!(TPM2_RC_REFERENCE_S4, ReferenceS4);
    test_valid_conversion!(TPM2_RC_REFERENCE_S5, ReferenceS5);
    test_valid_conversion!(TPM2_RC_REFERENCE_S6, ReferenceS6);
    test_valid_conversion!(TPM2_RC_NV_RATE, NvRate);
    test_valid_conversion!(TPM2_RC_LOCKOUT, Lockout);
    test_valid_conversion!(TPM2_RC_RETRY, Retry);
    test_valid_conversion!(TPM2_RC_NV_UNAVAILABLE, NvUnavailable);
}

#[test]
fn test_invalid_conversions() {
    /// Values from the specification without the TPM_RC_VER1.
    const VALID_VALUES: [u8; 28] = [
        0x1u8, 0x2u8, 0x3u8, 0x4u8, 0x5u8, 0x6u8, 0x7u8, 0x8u8, 0x9u8, 0xAu8, 0x10u8, 0x11u8,
        0x12u8, 0x13u8, 0x14u8, 0x15u8, 0x16u8, 0x18u8, 0x19u8, 0x1Au8, 0x1Bu8, 0x1Cu8, 0x1Du8,
        0x1Eu8, 0x20u8, 0x21u8, 0x22u8, 0x23u8,
    ];
    for item in 0..u8::MAX {
        if VALID_VALUES.contains(&item) {
            assert!(
                TpmFormatZeroWarning::try_from(item).is_ok(),
                "Converting {item} into TpmFormatZeroWarning did not result in Ok as expected",
            );
        } else {
            assert_eq!(
                Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
                TpmFormatZeroWarning::try_from(item),
                "Converting {item} into TpmFormatZeroWarning did not result in the expected error",
            );
        }
    }
}
