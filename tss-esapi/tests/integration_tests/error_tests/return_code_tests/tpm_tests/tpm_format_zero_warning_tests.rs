// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatZeroWarning,
        tss::{
            TPM2_RC_CANCELED, TPM2_RC_CONTEXT_GAP, TPM2_RC_LOCALITY, TPM2_RC_LOCKOUT,
            TPM2_RC_NOT_USED, TPM2_RC_NV_RATE, TPM2_RC_NV_UNAVAILABLE, TPM2_RC_OBJECT_HANDLES,
            TPM2_RC_OBJECT_MEMORY, TPM2_RC_REFERENCE_H0, TPM2_RC_REFERENCE_H1,
            TPM2_RC_REFERENCE_H2, TPM2_RC_REFERENCE_H3, TPM2_RC_REFERENCE_H4, TPM2_RC_REFERENCE_H5,
            TPM2_RC_REFERENCE_H6, TPM2_RC_REFERENCE_S0, TPM2_RC_REFERENCE_S1, TPM2_RC_REFERENCE_S2,
            TPM2_RC_REFERENCE_S3, TPM2_RC_REFERENCE_S4, TPM2_RC_REFERENCE_S5, TPM2_RC_REFERENCE_S6,
            TPM2_RC_RETRY, TPM2_RC_SESSION_MEMORY, TPM2_RC_TESTING, TPM2_RC_WARN, TPM2_RC_YIELDED,
            TSS2_TPM_RC_LAYER,
        },
    },
    error::{
        ReturnCode, TpmFormatZeroResponseCode, TpmFormatZeroWarningResponseCode, TpmResponseCode,
    },
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tpm_rc:ident, TpmFormatZeroWarning::$item:ident) => {
        let expected_tss_rc = TSS2_TPM_RC_LAYER | $tpm_rc;
        let expected_tpm_format_zero_warning_rc =
        TpmFormatZeroWarningResponseCode::from(TpmFormatZeroWarning::$item);

        assert_eq!(
            expected_tpm_format_zero_warning_rc,
            TpmFormatZeroWarningResponseCode::try_from(($tpm_rc - TPM2_RC_WARN) as u8).expect(
                &format!(
                    "{} did not convert into a TpmFormatZeroWarningResponseCode",
                    std::stringify!($tpm_rc - TPM2_RC_WARN)
                )
            ),
            "{} did not convert into the expected TpmFormatZeroWarningResponseCode",
            std::stringify!($tpm_rc - TPM2_RC_WARN),
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Tpm(TpmResponseCode::FormatZero(TpmFormatZeroResponseCode::Warning(
            actual_tpm_format_zero_warning_rc,
        ))) = actual_rc
        {
            assert_eq!(
                expected_tpm_format_zero_warning_rc,
                actual_tpm_format_zero_warning_rc,
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
            std::stringify!(TpmFormatZeroWarning::$item),
            std::stringify!($tpm_rc),
        );
    };
}

macro_rules! test_display_trait_impl {
    ($expected_error_message:tt, TpmFormatZeroWarning::$zero_warning:ident) => {
        assert_eq!(
            format!(
                "{}",
                TpmFormatZeroWarningResponseCode::from(TpmFormatZeroWarning::$zero_warning)
            ),
            $expected_error_message,
            "TpmFormatZeroWarningResponseCode with {} did not produce the expected error message",
            std::stringify!(TpmFormatZeroWarning::$zero_warning),
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TPM2_RC_CONTEXT_GAP, TpmFormatZeroWarning::ContextGap);
    test_valid_conversion!(TPM2_RC_OBJECT_MEMORY, TpmFormatZeroWarning::ObjectMemory);
    test_valid_conversion!(TPM2_RC_SESSION_MEMORY, TpmFormatZeroWarning::SessionMemory);
    test_valid_conversion!(TPM2_RC_OBJECT_HANDLES, TpmFormatZeroWarning::ObjectHandles);
    test_valid_conversion!(TPM2_RC_LOCALITY, TpmFormatZeroWarning::Locality);
    test_valid_conversion!(TPM2_RC_YIELDED, TpmFormatZeroWarning::Yielded);
    test_valid_conversion!(TPM2_RC_CANCELED, TpmFormatZeroWarning::Canceled);
    test_valid_conversion!(TPM2_RC_TESTING, TpmFormatZeroWarning::Testing);
    test_valid_conversion!(TPM2_RC_REFERENCE_H0, TpmFormatZeroWarning::ReferenceH0);
    test_valid_conversion!(TPM2_RC_REFERENCE_H1, TpmFormatZeroWarning::ReferenceH1);
    test_valid_conversion!(TPM2_RC_REFERENCE_H2, TpmFormatZeroWarning::ReferenceH2);
    test_valid_conversion!(TPM2_RC_REFERENCE_H3, TpmFormatZeroWarning::ReferenceH3);
    test_valid_conversion!(TPM2_RC_REFERENCE_H4, TpmFormatZeroWarning::ReferenceH4);
    test_valid_conversion!(TPM2_RC_REFERENCE_H5, TpmFormatZeroWarning::ReferenceH5);
    test_valid_conversion!(TPM2_RC_REFERENCE_H6, TpmFormatZeroWarning::ReferenceH6);
    test_valid_conversion!(TPM2_RC_REFERENCE_S0, TpmFormatZeroWarning::ReferenceS0);
    test_valid_conversion!(TPM2_RC_REFERENCE_S1, TpmFormatZeroWarning::ReferenceS1);
    test_valid_conversion!(TPM2_RC_REFERENCE_S2, TpmFormatZeroWarning::ReferenceS2);
    test_valid_conversion!(TPM2_RC_REFERENCE_S3, TpmFormatZeroWarning::ReferenceS3);
    test_valid_conversion!(TPM2_RC_REFERENCE_S4, TpmFormatZeroWarning::ReferenceS4);
    test_valid_conversion!(TPM2_RC_REFERENCE_S5, TpmFormatZeroWarning::ReferenceS5);
    test_valid_conversion!(TPM2_RC_REFERENCE_S6, TpmFormatZeroWarning::ReferenceS6);
    test_valid_conversion!(TPM2_RC_NV_RATE, TpmFormatZeroWarning::NvRate);
    test_valid_conversion!(TPM2_RC_LOCKOUT, TpmFormatZeroWarning::Lockout);
    test_valid_conversion!(TPM2_RC_RETRY, TpmFormatZeroWarning::Retry);
    test_valid_conversion!(TPM2_RC_NV_UNAVAILABLE, TpmFormatZeroWarning::NvUnavailable);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_tpm_format_zero_error_rc = TSS2_TPM_RC_LAYER | TPM2_RC_NOT_USED;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_tpm_format_zero_error_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid TPM layer response code did not produce the expected error"
    );
}

#[test]
fn test_display_implementation() {
    test_display_trait_impl!(
        "Gap for context ID is too large.",
        TpmFormatZeroWarning::ContextGap
    );
    test_display_trait_impl!(
        "Out of memory for object contexts.",
        TpmFormatZeroWarning::ObjectMemory
    );
    test_display_trait_impl!(
        "Out of memory for session contexts.",
        TpmFormatZeroWarning::SessionMemory
    );
    test_display_trait_impl!(
        "Out of shared object or session memory or need space for internal operations.",
        TpmFormatZeroWarning::Memory
    );
    test_display_trait_impl!(
        "Out of session handles.",
        TpmFormatZeroWarning::SessionHandles
    );
    test_display_trait_impl!(
        "Out of object handles.",
        TpmFormatZeroWarning::ObjectHandles
    );
    test_display_trait_impl!("Bad locality.", TpmFormatZeroWarning::Locality);
    test_display_trait_impl!(
        "The TPM has suspended operation on the command; forward progress was made and the command may be retried.",
        TpmFormatZeroWarning::Yielded
    );
    test_display_trait_impl!("The command was canceled.", TpmFormatZeroWarning::Canceled);
    test_display_trait_impl!(
        "TPM is performing self-tests.",
        TpmFormatZeroWarning::Testing
    );
    test_display_trait_impl!(
        "The 1st handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH0
    );
    test_display_trait_impl!(
        "The 2nd handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH1
    );
    test_display_trait_impl!(
        "The 3rd handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH2
    );
    test_display_trait_impl!(
        "The 4th handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH3
    );
    test_display_trait_impl!(
        "The 5th handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH4
    );
    test_display_trait_impl!(
        "The 6th handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH5
    );
    test_display_trait_impl!(
        "The 7th handle in the handle area references a transient object or session that is not loaded.",
        TpmFormatZeroWarning::ReferenceH6
    );

    test_display_trait_impl!(
        "The 1st authorization session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS0
    );
    test_display_trait_impl!(
        "The 2nd authorization session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS1
    );
    test_display_trait_impl!(
        "The 3rd authorization session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS2
    );
    test_display_trait_impl!(
        "The 4th authorization session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS3
    );
    test_display_trait_impl!(
        "The 5th session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS4
    );
    test_display_trait_impl!(
        "The 6th session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS5
    );
    test_display_trait_impl!(
        "The 7th authorization session handle references a session that is not loaded.",
        TpmFormatZeroWarning::ReferenceS6
    );
    test_display_trait_impl!(
        "The TPM is rate-limiting accesses to prevent wearout of NV.",
        TpmFormatZeroWarning::NvRate
    );
    test_display_trait_impl!(
        "Authorizations for objects subject to DA protection are not allowed at this time because the TPM is in DA lockout mode.",
        TpmFormatZeroWarning::Lockout
    );
    test_display_trait_impl!(
        "The TPM was not able to start the command.",
        TpmFormatZeroWarning::Retry
    );
    test_display_trait_impl!(
        "The command may require writing of NV and NV is not current accessible.",
        TpmFormatZeroWarning::NvUnavailable
    );
}
