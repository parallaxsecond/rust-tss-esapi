// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatZeroError,
        tss::{
            TPM2_RC_AUTHSIZE, TPM2_RC_AUTH_CONTEXT, TPM2_RC_AUTH_MISSING, TPM2_RC_AUTH_TYPE,
            TPM2_RC_AUTH_UNAVAILABLE, TPM2_RC_BAD_CONTEXT, TPM2_RC_COMMAND_CODE,
            TPM2_RC_COMMAND_SIZE, TPM2_RC_CPHASH, TPM2_RC_DISABLED, TPM2_RC_EXCLUSIVE,
            TPM2_RC_FAILURE, TPM2_RC_HMAC, TPM2_RC_INITIALIZE, TPM2_RC_NO_RESULT,
            TPM2_RC_NV_AUTHORIZATION, TPM2_RC_NV_DEFINED, TPM2_RC_NV_LOCKED, TPM2_RC_NV_RANGE,
            TPM2_RC_NV_SIZE, TPM2_RC_NV_SPACE, TPM2_RC_NV_UNINITIALIZED, TPM2_RC_PARENT,
            TPM2_RC_PCR, TPM2_RC_PCR_CHANGED, TPM2_RC_POLICY, TPM2_RC_PRIVATE, TPM2_RC_REBOOT,
            TPM2_RC_SENSITIVE, TPM2_RC_SEQUENCE, TPM2_RC_TOO_MANY_CONTEXTS, TPM2_RC_UNBALANCED,
            TPM2_RC_UPGRADE, TPM2_RC_VER1, TSS2_TPM_RC_LAYER,
        },
    },
    error::{
        ReturnCode, TpmFormatZeroErrorResponseCode, TpmFormatZeroResponseCode, TpmResponseCode,
    },
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tpm_rc:ident, TpmFormatZeroError::$item:ident) => {
        let expected_tss_rc = TSS2_TPM_RC_LAYER | $tpm_rc;
        let expected_tpm_format_zero_error_rc =
            TpmFormatZeroErrorResponseCode::from(TpmFormatZeroError::$item);

        assert_eq!(
            expected_tpm_format_zero_error_rc,
            TpmFormatZeroErrorResponseCode::try_from(($tpm_rc - TPM2_RC_VER1) as u8).expect(
                &format!(
                    "{} did not convert into a TpmFormatZeroErrorResponseCode",
                    std::stringify!($tpm_rc - TPM2_RC_VER1)
                )
            ),
            "{} did not convert into the expected TpmFormatZeroErrorResponseCode",
            std::stringify!($tpm_rc - TPM2_RC_VER1),
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Tpm(TpmResponseCode::FormatZero(TpmFormatZeroResponseCode::Error(
            actual_tpm_format_zero_error_rc,
        ))) = actual_rc
        {
            assert_eq!(
                expected_tpm_format_zero_error_rc,
                actual_tpm_format_zero_error_rc,
                "{} in the TPM layer did not convert into the expected TpmFormatZeroResponseCode",
                std::stringify!($tpm_rc)
            );
        } else {
            panic!("TPM TSS2_RC layer did no convert into ReturnCode::Tpm");
        }

        assert_eq!(
            expected_tss_rc,
            actual_rc.into(),
            "TpmFormatZeroResponseCode with {} did not convert into expected {} TSS2_RC in the TPM layer.",
            std::stringify!(TpmFormatZeroError::$item),
            std::stringify!($tpm_rc),
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_RC_INITIALIZE, TpmFormatZeroError::Initialize);
    test_valid_conversion!(TPM2_RC_FAILURE, TpmFormatZeroError::Failure);
    test_valid_conversion!(TPM2_RC_SEQUENCE, TpmFormatZeroError::Sequence);
    test_valid_conversion!(TPM2_RC_PRIVATE, TpmFormatZeroError::Private);
    test_valid_conversion!(TPM2_RC_HMAC, TpmFormatZeroError::Hmac);
    test_valid_conversion!(TPM2_RC_DISABLED, TpmFormatZeroError::Disabled);
    test_valid_conversion!(TPM2_RC_EXCLUSIVE, TpmFormatZeroError::Exclusive);
    test_valid_conversion!(TPM2_RC_AUTH_TYPE, TpmFormatZeroError::AuthType);
    test_valid_conversion!(TPM2_RC_AUTH_MISSING, TpmFormatZeroError::AuthMissing);
    test_valid_conversion!(TPM2_RC_POLICY, TpmFormatZeroError::Policy);
    test_valid_conversion!(TPM2_RC_PCR, TpmFormatZeroError::Pcr);
    test_valid_conversion!(TPM2_RC_PCR_CHANGED, TpmFormatZeroError::PcrChanged);
    test_valid_conversion!(TPM2_RC_UPGRADE, TpmFormatZeroError::Upgrade);
    test_valid_conversion!(
        TPM2_RC_TOO_MANY_CONTEXTS,
        TpmFormatZeroError::TooManyContexts
    );
    test_valid_conversion!(
        TPM2_RC_AUTH_UNAVAILABLE,
        TpmFormatZeroError::AuthUnavailable
    );
    test_valid_conversion!(TPM2_RC_REBOOT, TpmFormatZeroError::Reboot);
    test_valid_conversion!(TPM2_RC_UNBALANCED, TpmFormatZeroError::Unbalanced);
    test_valid_conversion!(TPM2_RC_COMMAND_SIZE, TpmFormatZeroError::CommandSize);
    test_valid_conversion!(TPM2_RC_COMMAND_CODE, TpmFormatZeroError::CommandCode);
    test_valid_conversion!(TPM2_RC_AUTHSIZE, TpmFormatZeroError::AuthSize);
    test_valid_conversion!(TPM2_RC_AUTH_CONTEXT, TpmFormatZeroError::AuthContext);
    test_valid_conversion!(TPM2_RC_NV_RANGE, TpmFormatZeroError::NvRange);
    test_valid_conversion!(TPM2_RC_NV_SIZE, TpmFormatZeroError::NvSize);
    test_valid_conversion!(TPM2_RC_NV_LOCKED, TpmFormatZeroError::NvLocked);
    test_valid_conversion!(
        TPM2_RC_NV_AUTHORIZATION,
        TpmFormatZeroError::NvAuthorization
    );
    test_valid_conversion!(
        TPM2_RC_NV_UNINITIALIZED,
        TpmFormatZeroError::NvUninitialized
    );
    test_valid_conversion!(TPM2_RC_NV_SPACE, TpmFormatZeroError::NvSpace);
    test_valid_conversion!(TPM2_RC_NV_DEFINED, TpmFormatZeroError::NvDefined);
    test_valid_conversion!(TPM2_RC_BAD_CONTEXT, TpmFormatZeroError::BadContext);
    test_valid_conversion!(TPM2_RC_CPHASH, TpmFormatZeroError::CpHash);
    test_valid_conversion!(TPM2_RC_PARENT, TpmFormatZeroError::Parent);
    test_valid_conversion!(TPM2_RC_NO_RESULT, TpmFormatZeroError::NoResult);
    test_valid_conversion!(TPM2_RC_SENSITIVE, TpmFormatZeroError::Sensitive);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_tpm_format_zero_error_rc = TSS2_TPM_RC_LAYER | (TPM2_RC_VER1 + 0x56);
    assert_eq!(
        ReturnCode::try_from(tss_invalid_tpm_format_zero_error_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid TPM layer response code did not produce the expected error"
    );
}
