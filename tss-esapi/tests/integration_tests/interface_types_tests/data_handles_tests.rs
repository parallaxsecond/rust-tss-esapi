// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use serial_test::serial;
use tss_esapi::{
    constants::tss::{
        TPM2_HMAC_SESSION_LAST, TPM2_PERMANENT_LAST, TPM2_POLICY_SESSION_LAST, TPM2_TRANSIENT_LAST,
        TPMI_DH_SAVED_SEQUENCE, TPMI_DH_SAVED_TRANSIENT, TPMI_DH_SAVED_TRANSIENT_CLEAR,
    },
    handles::{HmacSessionTpmHandle, PolicySessionTpmHandle, TransientTpmHandle},
    interface_types::data_handles::{ContextDataHandle, Saved},
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversions_for_range_enum_items {
    ($enum_type:ident::$enum_item:ident, $handle_type:ident, $tss:ident) => {
        let actual_enum_item = $enum_type::try_from($tss).unwrap_or_else(|_| {
            panic!(
                "Converting {} into {} should not cause an error.",
                std::stringify!($tss),
                std::any::type_name::<$enum_type>(),
            );
        });
        let expected_handle = $handle_type::try_from($tss).unwrap_or_else(|_| {
            panic!(
                "Converting {} into {} should not cause an error.",
                std::stringify!($tss),
                std::stringify!($handle_type)
            );
        });
        if let $enum_type::$enum_item(actual_handle) = actual_enum_item {
            assert_eq!(
                expected_handle,
                actual_handle,
                "{} was not converted into the expected handle.",
                std::stringify!($tss)
            );
        } else {
            panic!(
                "{} should convert into a {}.",
                std::stringify!($tss),
                std::stringify!($enum_type::$enum_item)
            );
        }
        assert_eq!(
            actual_enum_item,
            $enum_type::try_from(expected_handle).unwrap_or_else(|_| {
                panic!(
                    "Should be possible to convert {:?} into {}.",
                    expected_handle,
                    std::any::type_name::<$enum_type>()
                )
            })
        );
    };
}

macro_rules! test_valid_conversions_constant_handle_value {
    ($enum_type:ident::$enum_item:ident, $handle_type:ident::$constant_item:ident, $tss:ident) => {
        let actual_enum_item = $enum_type::try_from($tss).unwrap_or_else(|_| {
            panic!(
                "Converting {} into {} should not cause an error.",
                std::stringify!($tss),
                std::any::type_name::<$enum_type>(),
            );
        });
        let expected_handle = $handle_type::$constant_item;
        assert_eq!(
            actual_enum_item,
            $enum_type::try_from(expected_handle).unwrap_or_else(|_| {
                panic!(
                    "Should be possible to convert {:?} into {}.",
                    expected_handle,
                    std::any::type_name::<$enum_type>()
                )
            })
        );
    };
}

macro_rules! test_invalid_conversions {
    ($enum_type:ident, $invalid_value:ident, WrapperErrorKind::$error_kind:ident) => {
        let result = $enum_type::try_from($invalid_value);
        if let Err(error) = result {
            assert_eq!(
                Error::WrapperError(WrapperErrorKind::$error_kind),
                error,
                "Converting an invalid value {} did not produce the expected error: {}.",
                std::stringify!($invalid_value),
                std::stringify!(Error::WrapperError(WrapperErrorKind::$error_kind)),
            );
        } else {
            panic!(
                "Converting an invalid value {} did not produce an error.",
                std::stringify!($invalid_value)
            );
        }
    };
}

#[test]
#[serial]
fn test_context_data_handle_valid_conversions() {
    test_valid_conversions_for_range_enum_items!(
        ContextDataHandle::Hmac,
        HmacSessionTpmHandle,
        TPM2_HMAC_SESSION_LAST
    );
    test_valid_conversions_for_range_enum_items!(
        ContextDataHandle::Policy,
        PolicySessionTpmHandle,
        TPM2_POLICY_SESSION_LAST
    );
    test_valid_conversions_for_range_enum_items!(
        ContextDataHandle::Transient,
        TransientTpmHandle,
        TPM2_TRANSIENT_LAST
    );
}

#[test]
#[serial]
fn test_context_data_handle_invalid_conversion() {
    test_invalid_conversions!(
        ContextDataHandle,
        TPM2_PERMANENT_LAST,
        WrapperErrorKind::InvalidParam
    );
}

#[test]
#[serial]
fn test_saved_valid_conversions() {
    test_valid_conversions_for_range_enum_items!(
        Saved::Hmac,
        HmacSessionTpmHandle,
        TPM2_HMAC_SESSION_LAST
    );
    test_valid_conversions_for_range_enum_items!(
        Saved::Policy,
        PolicySessionTpmHandle,
        TPM2_POLICY_SESSION_LAST
    );
    test_valid_conversions_constant_handle_value!(
        Saved::Transient,
        TransientTpmHandle::SavedTransient,
        TPMI_DH_SAVED_TRANSIENT
    );
    test_valid_conversions_constant_handle_value!(
        Saved::Sequence,
        TransientTpmHandle::SavedSequence,
        TPMI_DH_SAVED_SEQUENCE
    );
    test_valid_conversions_constant_handle_value!(
        Saved::TransientClear,
        TransientTpmHandle::SavedTransientClear,
        TPMI_DH_SAVED_TRANSIENT_CLEAR
    );
}

#[test]
#[serial]
fn test_saved_invalid_conversions() {
    test_invalid_conversions!(Saved, TPM2_PERMANENT_LAST, WrapperErrorKind::InvalidParam);
    test_invalid_conversions!(Saved, TPM2_TRANSIENT_LAST, WrapperErrorKind::InvalidParam);
}
