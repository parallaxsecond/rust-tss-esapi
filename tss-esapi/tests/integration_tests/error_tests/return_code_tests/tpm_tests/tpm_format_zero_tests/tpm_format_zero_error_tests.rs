// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use bitfield::bitfield;
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
    tss2_esys::TSS2_RC,
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
                    "{} did not convert into a {}",
                    std::stringify!($tpm_rc - TPM2_RC_VER1),
                    std::any::type_name::<TpmFormatZeroErrorResponseCode>(),
                )
            ),
            "{} did not convert into the expected {}",
            std::stringify!($tpm_rc - TPM2_RC_VER1),
            std::any::type_name::<TpmFormatZeroErrorResponseCode>()
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
                "{} in the TPM layer did not convert into the expected {}",
                std::stringify!($tpm_rc),
                std::any::type_name::<TpmFormatZeroResponseCode>(),
            );
        } else {
            panic!("TPM TSS2_RC layer did no convert into ReturnCode::Tpm");
        }

        assert_eq!(
            expected_tss_rc,
            TSS2_RC::from(actual_rc),
            "{} with {} did not convert into expected {} TSS2_RC in the TPM layer.",
            std::any::type_name::<TpmFormatZeroResponseCode>(),
            std::stringify!(TpmFormatZeroError::$item),
            std::stringify!($tpm_rc),
        );
    };
}

macro_rules! test_display_trait_impl {
    ($expected_error_message:tt, TpmFormatZeroError::$zero_error:ident) => {
        assert_eq!(
            format!(
                "{}",
                TpmFormatZeroErrorResponseCode::from(TpmFormatZeroError::$zero_error)
            ),
            $expected_error_message,
            "{} with {} did not produce the expected error message",
            std::any::type_name::<TpmFormatZeroErrorResponseCode>(),
            std::stringify!(TpmFormatZeroError::$zero_error),
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

bitfield! {
    pub struct ReservedBitHelper(u32);
    _, set_reserved: 9;
}

#[test]
fn test_conversion_of_invalid_value_with_reserved_bits_set() {
    // Bit 9 In the TPM format zero return code is the reserved bit.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = ReservedBitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_reserved(true);
    let tss_rc_with_reserved_bit_set = helper.0;

    assert_eq!(
        ReturnCode::try_from(tss_rc_with_reserved_bit_set),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid TPM format zero error with reserve bit set did not result in the expected error."
    );
}

bitfield! {
    pub struct Tpm2BitHelper(u32);
    _, set_tpm_2_0: 8;
}

#[test]
fn test_conversion_of_invalid_value_without_tpm2_bit_set() {
    // Bit 9 In the TPM format zero return code is the reserved bit.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = Tpm2BitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_tpm_2_0(false);
    let tss_rc_with_tpm2_bit_clear = helper.0;

    assert_eq!(
        ReturnCode::try_from(tss_rc_with_tpm2_bit_clear),
        Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
        "Converting invalid TPM format zero error with TPM 2.0 bit clear did not result in the expected error."
    );
}

#[test]
fn test_display_implementation() {
    test_display_trait_impl!(
        "TPM not initialized by TPM2_Startup or already initialized.",
        TpmFormatZeroError::Initialize
    );
    test_display_trait_impl!(
        "Commands not accepted because of a TPM failure.",
        TpmFormatZeroError::Failure
    );
    test_display_trait_impl!(
        "Improper use of a sequence handle.",
        TpmFormatZeroError::Sequence
    );
    test_display_trait_impl!("Not currently used.", TpmFormatZeroError::Private);
    test_display_trait_impl!("Not currently used.", TpmFormatZeroError::Hmac);
    test_display_trait_impl!("The command is disabled.", TpmFormatZeroError::Disabled);
    test_display_trait_impl!(
        "Command failed because audit sequence required exclusivity.",
        TpmFormatZeroError::Exclusive
    );
    test_display_trait_impl!(
        "Authorization handle is not correct for command.",
        TpmFormatZeroError::AuthType
    );
    test_display_trait_impl!(
        "Command requires an authorization session for handle and it is not present.",
        TpmFormatZeroError::AuthMissing
    );
    test_display_trait_impl!(
        "Policy failure in math operation or an invalid `authPolicy` value.",
        TpmFormatZeroError::Policy
    );
    test_display_trait_impl!("PCR check fail.", TpmFormatZeroError::Pcr);
    test_display_trait_impl!(
        "PCR have changed since checked.",
        TpmFormatZeroError::PcrChanged
    );
    test_display_trait_impl!("For all commands other than TPM2_FieldUpgradeData(), this code indicates that the TPM is in field upgrade mode; for TPM2_FieldUpgradeData(), this code indicates that the TPM is not in field upgrade mode.", TpmFormatZeroError::Upgrade);
    test_display_trait_impl!(
        "Context ID counter is at maximum.",
        TpmFormatZeroError::TooManyContexts
    );
    test_display_trait_impl!(
        "`authValue` or `authPolicy` is not available for selected entity.",
        TpmFormatZeroError::AuthUnavailable
    );
    test_display_trait_impl!(
        "A _TPM_Init and Startup(CLEAR) is required before the TPM can resume operation.",
        TpmFormatZeroError::Reboot
    );
    test_display_trait_impl!("The protection algorithms (hash and symmetric) are not reasonably balanced. The digest size of the hash must be larger than the key size of the symmetric algorithm.", TpmFormatZeroError::Unbalanced);
    test_display_trait_impl!("Command `commandSize` value is inconsistent with contents of the command buffer; either the size is not the same as the octets loaded by the hardware interface layer or the value is not large enough to hold a command header.", TpmFormatZeroError::CommandSize);
    test_display_trait_impl!(
        "Command code not supported.",
        TpmFormatZeroError::CommandCode
    );
    test_display_trait_impl!("The value of `authorizationSize` is out of range or the number of octets in the authorization area is greater than required.", TpmFormatZeroError::AuthSize);
    test_display_trait_impl!("Use of an authorization session with a context command or another command that cannot have an authorization session.", TpmFormatZeroError::AuthContext);
    test_display_trait_impl!(
        "NV offset+size is out of range.",
        TpmFormatZeroError::NvRange
    );
    test_display_trait_impl!(
        "Requested allocation size is larger than allowed.",
        TpmFormatZeroError::NvSize
    );
    test_display_trait_impl!("NV access locked.", TpmFormatZeroError::NvLocked);
    test_display_trait_impl!(
        "NV access authorization fails in command actions.",
        TpmFormatZeroError::NvAuthorization
    );
    test_display_trait_impl!("An NV Index is used before being initialized or the state saved by TPM2_Shutdown(STATE) could not be restored.", TpmFormatZeroError::NvUninitialized);
    test_display_trait_impl!(
        "Insufficient space for NV allocation.",
        TpmFormatZeroError::NvSpace
    );
    test_display_trait_impl!(
        "NV Index or persistent object already defined.",
        TpmFormatZeroError::NvDefined
    );
    test_display_trait_impl!(
        "Context in TPM2_ContextLoad() is not valid.",
        TpmFormatZeroError::BadContext
    );
    test_display_trait_impl!(
        "`cpHash` value already set or not correct for use.",
        TpmFormatZeroError::CpHash
    );
    test_display_trait_impl!(
        "Handle for parent is not a valid parent.",
        TpmFormatZeroError::Parent
    );
    test_display_trait_impl!("Function needs testing.", TpmFormatZeroError::NeedsTest);
    test_display_trait_impl!("Function cannot process a request due to an unspecified problem. This code is usually related to invalid parameters that are not properly filtered by the input unmarshaling code.", TpmFormatZeroError::NoResult);
    test_display_trait_impl!(
        "The sensitive area did not unmarshal correctly after decryption.",
        TpmFormatZeroError::Sensitive
    );
}
