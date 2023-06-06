// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::TpmFormatOneError,
        tss::{
            TPM2_RC_1, TPM2_RC_2, TPM2_RC_3, TPM2_RC_4, TPM2_RC_5, TPM2_RC_6, TPM2_RC_7, TPM2_RC_8,
            TPM2_RC_9, TPM2_RC_A, TPM2_RC_ASYMMETRIC, TPM2_RC_ATTRIBUTES, TPM2_RC_AUTH_FAIL,
            TPM2_RC_B, TPM2_RC_BAD_AUTH, TPM2_RC_BINDING, TPM2_RC_C, TPM2_RC_CURVE, TPM2_RC_D,
            TPM2_RC_E, TPM2_RC_ECC_POINT, TPM2_RC_EXPIRED, TPM2_RC_F, TPM2_RC_H, TPM2_RC_HANDLE,
            TPM2_RC_HASH, TPM2_RC_HIERARCHY, TPM2_RC_INSUFFICIENT, TPM2_RC_INTEGRITY, TPM2_RC_KDF,
            TPM2_RC_KEY, TPM2_RC_KEY_SIZE, TPM2_RC_MGF, TPM2_RC_MODE, TPM2_RC_NONCE, TPM2_RC_P,
            TPM2_RC_POLICY_CC, TPM2_RC_POLICY_FAIL, TPM2_RC_PP, TPM2_RC_RANGE,
            TPM2_RC_RESERVED_BITS, TPM2_RC_S, TPM2_RC_SCHEME, TPM2_RC_SELECTOR, TPM2_RC_SIGNATURE,
            TPM2_RC_SIZE, TPM2_RC_SYMMETRIC, TPM2_RC_TAG, TPM2_RC_TICKET, TPM2_RC_TYPE,
            TPM2_RC_VALUE, TSS2_TPM_RC_LAYER,
        },
    },
    error::{ArgumentNumber, ReturnCode, TpmFormatOneResponseCode, TpmResponseCode},
};

macro_rules! test_valid_conversions_with_all_argument_combinations {
    ($tpm_error_rc:ident, TpmFormatOneError::$tpm_format_one_error_item:ident) => {
        test_valid_conversions_with_error_in_parameter_argument!($tpm_error_rc, TpmFormatOneError::$tpm_format_one_error_item, (TPM2_RC_1 1, TPM2_RC_2 2, TPM2_RC_3 3, TPM2_RC_4 4, TPM2_RC_5 5, TPM2_RC_6 6, TPM2_RC_7 7, TPM2_RC_8 8, TPM2_RC_9 9, TPM2_RC_A 10, TPM2_RC_B 11, TPM2_RC_C 12, TPM2_RC_D 13, TPM2_RC_E 14, TPM2_RC_F 15));
        test_valid_conversions_with_error_in_handle_argument!($tpm_error_rc, TpmFormatOneError::$tpm_format_one_error_item, (TPM2_RC_1 1, TPM2_RC_2 2, TPM2_RC_3 3, TPM2_RC_4 4, TPM2_RC_5 5, TPM2_RC_6 6, TPM2_RC_7 7));
        test_valid_conversions_with_error_in_session_argument!($tpm_error_rc, TpmFormatOneError::$tpm_format_one_error_item, (TPM2_RC_1 1, TPM2_RC_2 2, TPM2_RC_3 3, TPM2_RC_4 4, TPM2_RC_5 5, TPM2_RC_6 6, TPM2_RC_7 7));
    };
}

macro_rules! test_valid_conversions_with_error_in_parameter_argument {
    ($tpm_error_rc:ident, TpmFormatOneError::$tpm_format_one_error_item:ident, ($($tpm_associated_argument_value:ident $argument_number_value:expr),*)) => {
        $( test_valid_conversion!($tpm_error_rc, TPM2_RC_P, $tpm_associated_argument_value, TpmFormatOneError::$tpm_format_one_error_item, ArgumentNumber::Parameter, $argument_number_value); )*
    };
}

macro_rules! test_valid_conversions_with_error_in_handle_argument {
    ($tpm_error_rc:ident, TpmFormatOneError::$tpm_format_one_error_item:ident, ($($tpm_associated_argument_value:ident $argument_number_value:expr),*)) => {
        $( test_valid_conversion!($tpm_error_rc, TPM2_RC_H, $tpm_associated_argument_value, TpmFormatOneError::$tpm_format_one_error_item, ArgumentNumber::Handle, $argument_number_value); )*
    };
}

macro_rules! test_valid_conversions_with_error_in_session_argument {
    ($tpm_error_rc:ident, TpmFormatOneError::$tpm_format_one_error_item:ident, ($($tpm_associated_argument_value:ident $argument_number_value:expr),*)) => {
        $( test_valid_conversion!($tpm_error_rc, TPM2_RC_S, $tpm_associated_argument_value, TpmFormatOneError::$tpm_format_one_error_item, ArgumentNumber::Session, $argument_number_value); )*
    };
}

macro_rules! test_valid_conversion {
    ($tpm_error_rc:ident, $tpm_error_associated_argument:ident, $tpm_associated_argument_value:ident, TpmFormatOneError::$tpm_format_one_error_item:ident, ArgumentNumber::$argument_number_item:ident, $argument_number_value:expr) => {
        let expected_tss_rc = TSS2_TPM_RC_LAYER
            | ($tpm_error_rc + $tpm_error_associated_argument + $tpm_associated_argument_value);
        let expected_tpm_format_one_error_rc = TpmFormatOneResponseCode::new(
            TpmFormatOneError::$tpm_format_one_error_item,
            ArgumentNumber::$argument_number_item($argument_number_value),
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc).expect(&format!(
            "Failed to convert {} TSS2_RC into a ReturnCode",
            std::stringify!(
                TSS2_TPM_RC_LAYER
                    | ($tpm_error_rc
                        + $tpm_error_associated_argument
                        + $tpm_associated_argument_value)
            )
        ));

        if let ReturnCode::Tpm(TpmResponseCode::FormatOne(actual_tpm_format_one_error_rc)) = actual_rc {
            assert_eq!(
                expected_tpm_format_one_error_rc,
                actual_tpm_format_one_error_rc,
                "{} associated with {} nr {} did not convert into the expected TpmFormatOneResponseCode",
                std::stringify!($tpm_error_rc),
                std::stringify!($argument_number_item),
                std::stringify!($argument_number_value),
            );
        } else {
            panic!("TPM TSS2_RC layer did no convert into ReturnCode::Tpm");
        }

        assert_eq!(
            expected_tss_rc,
            actual_rc.into(),
            "TpmFormatOneResponseCode with {} and {} in the TPM layer did not convert into the expected TSS2_RC",
            std::stringify!(TpmFormatOneError::$tpm_format_one_error_item),
            std::stringify!(ArgumentNumber::$argument_number_item),
        );
    };
}

macro_rules! test_display_trait_impl {
    ($expected_error_message:tt, TpmFormatOneError::$zero_error:ident) => {
        assert_eq!(
            format!(
                "{}",
                TpmFormatOneResponseCode::new(
                    TpmFormatOneError::$zero_error,
                    ArgumentNumber::Parameter(1)
                )
            ),
            format!(
                "{} ({}).",
                $expected_error_message,
                ArgumentNumber::Parameter(1)
            ),
            "{} with {} did not produce the expected error message",
            std::any::type_name::<TpmFormatOneResponseCode>(),
            std::stringify!(TpmFormatOneError::$zero_error),
        );
    };
}

// The different tests needs to be split up because the compiler goes nuts
// otherwise.

#[test]
fn test_format_one_asymmetric_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_ASYMMETRIC,
        TpmFormatOneError::Asymmetric
    );
}

#[test]
fn test_format_one_attributes_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_ATTRIBUTES,
        TpmFormatOneError::Attributes
    );
}

#[test]
fn test_format_one_hash_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_HASH, TpmFormatOneError::Hash);
}

#[test]
fn test_format_one_value_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_VALUE, TpmFormatOneError::Value);
}

#[test]
fn test_format_one_hierarchy_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_HIERARCHY,
        TpmFormatOneError::Hierarchy
    );
}

#[test]
fn test_format_one_key_size_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_KEY_SIZE,
        TpmFormatOneError::KeySize
    );
}

#[test]
fn test_format_one_mgf_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_MGF, TpmFormatOneError::Mgf);
}

#[test]
fn test_format_one_mode_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_MODE, TpmFormatOneError::Mode);
}

#[test]
fn test_format_one_type_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_TYPE, TpmFormatOneError::Type);
}

#[test]
fn test_format_one_handle_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_HANDLE,
        TpmFormatOneError::Handle
    );
}

#[test]
fn test_format_one_kdf_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_KDF, TpmFormatOneError::Kdf);
}

#[test]
fn test_format_one_range_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_RANGE, TpmFormatOneError::Range);
}

#[test]
fn test_format_one_auth_fail_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_AUTH_FAIL,
        TpmFormatOneError::AuthFail
    );
}

#[test]
fn test_format_one_nonce_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_NONCE, TpmFormatOneError::Nonce);
}

#[test]
fn test_format_one_pp_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_PP, TpmFormatOneError::Pp);
}

#[test]
fn test_format_one_scheme_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_SCHEME,
        TpmFormatOneError::Scheme
    );
}

#[test]
fn test_format_one_size_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_SIZE, TpmFormatOneError::Size);
}

#[test]
fn test_format_one_symmetric_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_SYMMETRIC,
        TpmFormatOneError::Symmetric
    );
}

#[test]
fn test_format_one_tag_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_TAG, TpmFormatOneError::Tag);
}

#[test]
fn test_format_one_selector_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_SELECTOR,
        TpmFormatOneError::Selector
    );
}

#[test]
fn test_format_one_insufficient_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_INSUFFICIENT,
        TpmFormatOneError::Insufficient
    );
}

#[test]
fn test_format_one_signature_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_SIGNATURE,
        TpmFormatOneError::Signature
    );
}

#[test]
fn test_format_one_key_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_KEY, TpmFormatOneError::Key);
}

#[test]
fn test_format_one_policy_fail_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_POLICY_FAIL,
        TpmFormatOneError::PolicyFail
    );
}

#[test]
fn test_format_one_integrity_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_INTEGRITY,
        TpmFormatOneError::Integrity
    );
}

#[test]
fn test_format_one_ticket_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_TICKET,
        TpmFormatOneError::Ticket
    );
}

#[test]
fn test_format_one_reserved_bits_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_RESERVED_BITS,
        TpmFormatOneError::ReservedBits
    );
}

#[test]
fn test_format_one_bad_auth_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_BAD_AUTH,
        TpmFormatOneError::BadAuth
    );
}

#[test]
fn test_format_one_expired_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_EXPIRED,
        TpmFormatOneError::Expired
    );
}

#[test]
fn test_format_one_policy_cc_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_POLICY_CC,
        TpmFormatOneError::PolicyCc
    );
}

#[test]
fn test_format_one_binding_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_BINDING,
        TpmFormatOneError::Binding
    );
}

#[test]
fn test_format_one_curve_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(TPM2_RC_CURVE, TpmFormatOneError::Curve);
}

#[test]
fn test_format_one_ecc_point_error_valid_conversions() {
    test_valid_conversions_with_all_argument_combinations!(
        TPM2_RC_ECC_POINT,
        TpmFormatOneError::EccPoint
    );
}

#[test]
fn test_display_implementation() {
    test_display_trait_impl!(
        "Asymmetric algorithm not supported or not correct",
        TpmFormatOneError::Asymmetric
    );
    test_display_trait_impl!("Inconsistent attributes", TpmFormatOneError::Attributes);
    test_display_trait_impl!(
        "Hash algorithm not supported or not appropriate",
        TpmFormatOneError::Hash
    );
    test_display_trait_impl!(
        "Value is out of range or is not correct for the context",
        TpmFormatOneError::Value
    );
    test_display_trait_impl!(
        "Hierarchy is not enabled or is not correct for the use",
        TpmFormatOneError::Hierarchy
    );
    test_display_trait_impl!("Key size is not supported", TpmFormatOneError::KeySize);
    test_display_trait_impl!(
        "Mask generation function not supported",
        TpmFormatOneError::Mgf
    );
    test_display_trait_impl!("Mode of operation not supported", TpmFormatOneError::Mode);
    test_display_trait_impl!(
        "The type of the value is not appropriate for the use",
        TpmFormatOneError::Type
    );
    test_display_trait_impl!(
        "The handle is not correct for the use",
        TpmFormatOneError::Handle
    );
    test_display_trait_impl!(
        "Unsupported key derivation function or function not appropriate for use",
        TpmFormatOneError::Kdf
    );
    test_display_trait_impl!("Value was out of allowed range", TpmFormatOneError::Range);
    test_display_trait_impl!(
        "The authorization HMAC check failed and DA counter incremented",
        TpmFormatOneError::AuthFail
    );
    test_display_trait_impl!(
        "Invalid nonce size or nonce value mismatch",
        TpmFormatOneError::Nonce
    );
    test_display_trait_impl!(
        "Authorization requires assertion of PP",
        TpmFormatOneError::Pp
    );
    test_display_trait_impl!(
        "Unsupported or incompatible scheme",
        TpmFormatOneError::Scheme
    );
    test_display_trait_impl!("Structure is the wrong size", TpmFormatOneError::Size);
    test_display_trait_impl!(
        "Unsupported symmetric algorithm or key size, or not appropriate for instance",
        TpmFormatOneError::Symmetric
    );
    test_display_trait_impl!("Incorrect structure tag", TpmFormatOneError::Tag);
    test_display_trait_impl!("Union selector is incorrect", TpmFormatOneError::Selector);
    test_display_trait_impl!("The TPM was unable to unmarshal a value because there were not enough octets in the input buffer", TpmFormatOneError::Insufficient);
    test_display_trait_impl!("The signature is not valid", TpmFormatOneError::Signature);
    test_display_trait_impl!(
        "Key fields are not compatible with the selected use",
        TpmFormatOneError::Key
    );
    test_display_trait_impl!("A policy check failed", TpmFormatOneError::PolicyFail);
    test_display_trait_impl!("Integrity check failed", TpmFormatOneError::Integrity);
    test_display_trait_impl!("Invalid ticket", TpmFormatOneError::Ticket);
    test_display_trait_impl!(
        "Reserved bits not set to zero as required",
        TpmFormatOneError::ReservedBits
    );
    test_display_trait_impl!(
        "Authorization failure without DA implications",
        TpmFormatOneError::BadAuth
    );
    test_display_trait_impl!("The policy has expired", TpmFormatOneError::Expired);
    test_display_trait_impl!("The `commandCode` in the policy is not the `commandCode` of the command or the command code in a policy command references a command that is not implemented", TpmFormatOneError::PolicyCc);
    test_display_trait_impl!(
        "Public and sensitive portions of an object are not cryptographically bound",
        TpmFormatOneError::Binding
    );
    test_display_trait_impl!("Curve not supported", TpmFormatOneError::Curve);
    test_display_trait_impl!(
        "Point is not on the required curve",
        TpmFormatOneError::EccPoint
    );
}
