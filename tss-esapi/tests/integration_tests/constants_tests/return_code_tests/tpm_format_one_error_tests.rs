// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use bitfield::bitfield;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatOneError,
        tss::{
            TPM2_RC_ASYMMETRIC, TPM2_RC_ATTRIBUTES, TPM2_RC_AUTH_FAIL, TPM2_RC_BAD_AUTH,
            TPM2_RC_BINDING, TPM2_RC_CURVE, TPM2_RC_ECC_POINT, TPM2_RC_EXPIRED, TPM2_RC_HANDLE,
            TPM2_RC_HASH, TPM2_RC_HIERARCHY, TPM2_RC_INSUFFICIENT, TPM2_RC_INTEGRITY, TPM2_RC_KDF,
            TPM2_RC_KEY, TPM2_RC_KEY_SIZE, TPM2_RC_MGF, TPM2_RC_MODE, TPM2_RC_NONCE,
            TPM2_RC_POLICY_CC, TPM2_RC_POLICY_FAIL, TPM2_RC_PP, TPM2_RC_RANGE,
            TPM2_RC_RESERVED_BITS, TPM2_RC_SCHEME, TPM2_RC_SELECTOR, TPM2_RC_SIGNATURE,
            TPM2_RC_SIZE, TPM2_RC_SYMMETRIC, TPM2_RC_TAG, TPM2_RC_TICKET, TPM2_RC_TYPE,
            TPM2_RC_VALUE,
        },
    },
    Error, WrapperErrorKind,
};

bitfield! {
    #[derive(PartialEq, Copy, Clone)]
    struct TpmFormatOneRc(u16);
    u8, error_number, set_error_number: 5, 0;
}

macro_rules! test_valid_conversion {
    ($tpm_fmt1_rc:ident, $item:ident) => {
        let tpm_rc = TpmFormatOneRc($tpm_fmt1_rc as u16);
        assert_eq!(
            tpm_rc.error_number(),
            u8::from(TpmFormatOneError::$item),
            "Conversion of {} into a u16 value without TPM2_RC_FMT1 did not produce the expected value {}",
            std::stringify!(TpmFormatOneError::$item),
            tpm_rc.error_number()
        );
        assert_eq!(
            TpmFormatOneError::$item,
            TpmFormatOneError::try_from(tpm_rc.error_number())
                .expect(&format!("Failed to convert the u16 value {} into TpmFormatOneError", tpm_rc.error_number())),
            "Conversion of {} into TpmFormatOneError did not produce the expected {}",
            tpm_rc.error_number(),
            std::stringify!(TpmFormatOneError::$item)
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_RC_ASYMMETRIC, Asymmetric);
    test_valid_conversion!(TPM2_RC_ATTRIBUTES, Attributes);
    test_valid_conversion!(TPM2_RC_HASH, Hash);
    test_valid_conversion!(TPM2_RC_VALUE, Value);
    test_valid_conversion!(TPM2_RC_HIERARCHY, Hierarchy);
    test_valid_conversion!(TPM2_RC_KEY_SIZE, KeySize);
    test_valid_conversion!(TPM2_RC_MGF, Mgf);
    test_valid_conversion!(TPM2_RC_MODE, Mode);
    test_valid_conversion!(TPM2_RC_TYPE, Type);
    test_valid_conversion!(TPM2_RC_HANDLE, Handle);
    test_valid_conversion!(TPM2_RC_KDF, Kdf);
    test_valid_conversion!(TPM2_RC_RANGE, Range);
    test_valid_conversion!(TPM2_RC_AUTH_FAIL, AuthFail);
    test_valid_conversion!(TPM2_RC_NONCE, Nonce);
    test_valid_conversion!(TPM2_RC_PP, Pp);
    test_valid_conversion!(TPM2_RC_SCHEME, Scheme);
    test_valid_conversion!(TPM2_RC_SIZE, Size);
    test_valid_conversion!(TPM2_RC_SYMMETRIC, Symmetric);
    test_valid_conversion!(TPM2_RC_TAG, Tag);
    test_valid_conversion!(TPM2_RC_SELECTOR, Selector);
    test_valid_conversion!(TPM2_RC_INSUFFICIENT, Insufficient);
    test_valid_conversion!(TPM2_RC_SIGNATURE, Signature);
    test_valid_conversion!(TPM2_RC_KEY, Key);
    test_valid_conversion!(TPM2_RC_POLICY_FAIL, PolicyFail);
    test_valid_conversion!(TPM2_RC_INTEGRITY, Integrity);
    test_valid_conversion!(TPM2_RC_TICKET, Ticket);
    test_valid_conversion!(TPM2_RC_RESERVED_BITS, ReservedBits);
    test_valid_conversion!(TPM2_RC_BAD_AUTH, BadAuth);
    test_valid_conversion!(TPM2_RC_EXPIRED, Expired);
    test_valid_conversion!(TPM2_RC_POLICY_CC, PolicyCc);
    test_valid_conversion!(TPM2_RC_BINDING, Binding);
    test_valid_conversion!(TPM2_RC_CURVE, Curve);
    test_valid_conversion!(TPM2_RC_ECC_POINT, EccPoint);
}

#[test]
fn test_invalid_conversions() {
    /// Values from the specification without the TPM_RC_FMT1.
    const VALID_VALUES: [u8; 33] = [
        0x1, 0x2, 0x3, 0x4, 0x5, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF, 0x10, 0x12, 0x15,
        0x16, 0x17, 0x18, 0x1A, 0x1B, 0x1C, 0x1D, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
        0x27,
    ];

    for item in 0..u8::MAX {
        if VALID_VALUES.contains(&item) {
            assert!(
                TpmFormatOneError::try_from(item).is_ok(),
                "Converting {} into TpmFormatOneError did not result in Ok as expected",
                item
            );
        } else {
            assert_eq!(
                Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
                TpmFormatOneError::try_from(item),
                "Converting {} into TpmFormatOneError did not result in the expected error",
                item
            );
        }
    }
}
