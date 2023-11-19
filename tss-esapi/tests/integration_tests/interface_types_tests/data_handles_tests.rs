// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{
        TPM2_HMAC_SESSION_LAST, TPM2_PERMANENT_LAST, TPM2_POLICY_SESSION_LAST, TPM2_TRANSIENT_LAST,
    },
    handles::{HmacSessionTpmHandle, PolicySessionTpmHandle, TransientTpmHandle},
    interface_types::data_handles::ContextDataHandle,
    Error, WrapperErrorKind,
};

macro_rules! context_data_handle_valid_conversions {
    (ContextDataHandle::$enum_item:ident, $handle_type:ident, $tss:ident) => {
        let context_data_handle = ContextDataHandle::try_from($tss).unwrap_or_else(|_| {
            panic!(
                "Converting {} into ContextDataHandle should not cause an error.",
                std::stringify!($tss)
            );
        });
        let expected_handle = $handle_type::try_from($tss).unwrap_or_else(|_| {
            panic!(
                "Converting {} into {} should not cause an error.",
                std::stringify!($tss),
                std::stringify!($handle_type)
            );
        });
        if let ContextDataHandle::$enum_item(actual_handle) = context_data_handle {
            assert_eq!(
                expected_handle,
                actual_handle,
                "{} was converted into the expected handle.",
                std::stringify!($tss)
            );
        } else {
            panic!(
                "{} should convert into a {}",
                std::stringify!($tss),
                std::stringify!(ContextDataHandle::$enum_item)
            );
        }
        assert_eq!(
            context_data_handle,
            ContextDataHandle::from(expected_handle)
        );
    };
}

#[test]
fn test_context_data_handle_valid_conversions() {
    context_data_handle_valid_conversions!(
        ContextDataHandle::Hmac,
        HmacSessionTpmHandle,
        TPM2_HMAC_SESSION_LAST
    );
    context_data_handle_valid_conversions!(
        ContextDataHandle::Policy,
        PolicySessionTpmHandle,
        TPM2_POLICY_SESSION_LAST
    );
    context_data_handle_valid_conversions!(
        ContextDataHandle::Transient,
        TransientTpmHandle,
        TPM2_TRANSIENT_LAST
    );
}

#[test]
fn test_context_data_handle_invalid_conversion() {
    let result = ContextDataHandle::try_from(TPM2_PERMANENT_LAST);
    if let Err(error) = result {
        assert_eq!(Error::WrapperError(WrapperErrorKind::InvalidParam), error);
    } else {
        panic!("Converting an invalid value `TPM2_PERMANENT_LAST` into a ContextDataHandle should produce an error.");
    }
}
