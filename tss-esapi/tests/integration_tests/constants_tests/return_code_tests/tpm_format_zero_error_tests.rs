// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use bitfield::bitfield;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatZeroError,
        tss::{
            TPM2_RC_AUTHSIZE, TPM2_RC_AUTH_CONTEXT, TPM2_RC_AUTH_MISSING, TPM2_RC_AUTH_TYPE,
            TPM2_RC_AUTH_UNAVAILABLE, TPM2_RC_BAD_CONTEXT, TPM2_RC_COMMAND_CODE,
            TPM2_RC_COMMAND_SIZE, TPM2_RC_CPHASH, TPM2_RC_DISABLED, TPM2_RC_EXCLUSIVE,
            TPM2_RC_FAILURE, TPM2_RC_HMAC, TPM2_RC_INITIALIZE, TPM2_RC_NEEDS_TEST,
            TPM2_RC_NO_RESULT, TPM2_RC_NV_AUTHORIZATION, TPM2_RC_NV_DEFINED, TPM2_RC_NV_LOCKED,
            TPM2_RC_NV_RANGE, TPM2_RC_NV_SIZE, TPM2_RC_NV_SPACE, TPM2_RC_NV_UNINITIALIZED,
            TPM2_RC_PARENT, TPM2_RC_PCR, TPM2_RC_PCR_CHANGED, TPM2_RC_POLICY, TPM2_RC_PRIVATE,
            TPM2_RC_REBOOT, TPM2_RC_SENSITIVE, TPM2_RC_SEQUENCE, TPM2_RC_TOO_MANY_CONTEXTS,
            TPM2_RC_UNBALANCED, TPM2_RC_UPGRADE,
        },
    },
    Error, WrapperErrorKind,
};

bitfield! {
    #[derive(PartialEq, Copy, Clone)]
    struct TpmFormatZeroErrorRc(u16);
    u8, error_number, set_error_number: 6, 0;
}

macro_rules! test_valid_conversion {
    ($tpm_ver1_rc:ident, $item:ident) => {
        let tpm_rc = TpmFormatZeroErrorRc($tpm_ver1_rc as u16);
        assert_eq!(
            tpm_rc.error_number(),
            TpmFormatZeroError::$item.into(),
            "Conversion of {} into a u16 value without TPM2_RC_VER1 did not produce the expected value {}",
            std::stringify!(TpmFormatZeroError::$item),
            tpm_rc.error_number()
        );
        assert_eq!(
            TpmFormatZeroError::$item,
            TpmFormatZeroError::try_from(tpm_rc.error_number())
                .expect(&format!("Failed to convert the u16 value {} into TpmFormatZeroError", tpm_rc.error_number())),
            "Conversion of {} into TpmFormatZeroError did not produce the expected {}",
            tpm_rc.error_number(),
            std::stringify!(TpmFormatZeroError::$item)
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_RC_INITIALIZE, Initialize);
    test_valid_conversion!(TPM2_RC_FAILURE, Failure);
    test_valid_conversion!(TPM2_RC_SEQUENCE, Sequence);
    test_valid_conversion!(TPM2_RC_PRIVATE, Private);
    test_valid_conversion!(TPM2_RC_HMAC, Hmac);
    test_valid_conversion!(TPM2_RC_DISABLED, Disabled);
    test_valid_conversion!(TPM2_RC_EXCLUSIVE, Exclusive);
    test_valid_conversion!(TPM2_RC_AUTH_TYPE, AuthType);
    test_valid_conversion!(TPM2_RC_AUTH_MISSING, AuthMissing);
    test_valid_conversion!(TPM2_RC_POLICY, Policy);
    test_valid_conversion!(TPM2_RC_PCR, Pcr);
    test_valid_conversion!(TPM2_RC_PCR_CHANGED, PcrChanged);
    test_valid_conversion!(TPM2_RC_UPGRADE, Upgrade);
    test_valid_conversion!(TPM2_RC_TOO_MANY_CONTEXTS, TooManyContexts);
    test_valid_conversion!(TPM2_RC_AUTH_UNAVAILABLE, AuthUnavailable);
    test_valid_conversion!(TPM2_RC_REBOOT, Reboot);
    test_valid_conversion!(TPM2_RC_UNBALANCED, Unbalanced);
    test_valid_conversion!(TPM2_RC_COMMAND_SIZE, CommandSize);
    test_valid_conversion!(TPM2_RC_COMMAND_CODE, CommandCode);
    test_valid_conversion!(TPM2_RC_AUTHSIZE, AuthSize);
    test_valid_conversion!(TPM2_RC_AUTH_CONTEXT, AuthContext);
    test_valid_conversion!(TPM2_RC_NV_RANGE, NvRange);
    test_valid_conversion!(TPM2_RC_NV_SIZE, NvSize);
    test_valid_conversion!(TPM2_RC_NV_LOCKED, NvLocked);
    test_valid_conversion!(TPM2_RC_NV_AUTHORIZATION, NvAuthorization);
    test_valid_conversion!(TPM2_RC_NV_UNINITIALIZED, NvUninitialized);
    test_valid_conversion!(TPM2_RC_NV_SPACE, NvSpace);
    test_valid_conversion!(TPM2_RC_NV_DEFINED, NvDefined);
    test_valid_conversion!(TPM2_RC_BAD_CONTEXT, BadContext);
    test_valid_conversion!(TPM2_RC_CPHASH, CpHash);
    test_valid_conversion!(TPM2_RC_PARENT, Parent);
    test_valid_conversion!(TPM2_RC_NEEDS_TEST, NeedsTest);
    test_valid_conversion!(TPM2_RC_NO_RESULT, NoResult);
    test_valid_conversion!(TPM2_RC_SENSITIVE, Sensitive);
}

#[test]
fn test_invalid_conversions() {
    /// Values from the specification without the TPM_RC_WARN.
    const VALID_VALUES: [u8; 34] = [
        0x0, 0x1, 0x3, 0xB, 0x19, 0x20, 0x21, 0x24, 0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x2F, 0x30,
        0x31, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x50, 0x51, 0x52,
        0x53, 0x54, 0x55,
    ];

    for item in 0..u8::MAX {
        if VALID_VALUES.contains(&item) {
            assert!(
                TpmFormatZeroError::try_from(item).is_ok(),
                "Converting {} into TpmFormatZeroError did not result in Ok as expected",
                item
            );
        } else {
            assert_eq!(
                Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
                TpmFormatZeroError::try_from(item),
                "Converting {} into TpmFormatZeroError did not result in the expected error",
                item
            );
        }
    }
}
