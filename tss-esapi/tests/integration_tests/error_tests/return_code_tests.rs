// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod base_tests;
mod esapi_tests;
mod fapi_tests;
mod muapi_tests;
mod resource_manager_tests;
mod resource_manager_tpm_tests;
mod sapi_tests;
mod tcti_tests;
mod tpm_tests;
use serial_test::serial;

use tss_esapi::{
    constants::tss::{
        TPM2_RC_INITIALIZE, TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE,
        TSS2_ESYS_RC_LAYER, TSS2_FEATURE_RC_LAYER, TSS2_MU_RC_LAYER, TSS2_RESMGR_RC_LAYER,
        TSS2_RESMGR_TPM_RC_LAYER, TSS2_SYS_RC_LAYER, TSS2_TCTI_RC_LAYER, TSS2_TPM_RC_LAYER,
    },
    error::{
        BaseReturnCode, EsapiReturnCode, FapiReturnCode, MuapiReturnCode, ReturnCode,
        SapiReturnCode, TctiReturnCode, TpmResponseCode,
    },
};

use std::{convert::TryFrom, error::Error};

macro_rules! test_error_trait_impl {
    ($native_rc:ident, $tss_rc_layer:ident, $tss_rc:ident) => {
        let return_code = ReturnCode::try_from($tss_rc_layer | $tss_rc).unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} error in {} layer return code into a ReturnCode object.",
                std::stringify!($tss_rc),
                std::stringify!($tss_rc_layer)
            )
        });

        let response_code = $native_rc::try_from(u16::try_from($tss_rc).unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} into a u16 value.",
                std::stringify!($tss_rc)
            )
        }))
        .unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} into a {}.",
                std::stringify!($tss_rc),
                std::any::type_name::<$native_rc>()
            )
        });

        assert_eq!(
            format!(
                "{}",
                return_code.source().unwrap_or_else(|| {
                    panic!(
                        "`source` function for a {} layer return code should not return None.",
                        std::stringify!($tss_rc_layer)
                    )
                })
            ),
            format!("{}", response_code),
            "Tss2_RC with from {} error in {} layer did not convert into the expected type {}",
            std::stringify!($tss_rc),
            std::stringify!($tss_rc_layer),
            std::any::type_name::<$native_rc>()
        );
    };
}

#[test]
#[serial]
fn test_error_trait_implementation() {
    test_error_trait_impl!(TpmResponseCode, TSS2_TPM_RC_LAYER, TPM2_RC_INITIALIZE);
    test_error_trait_impl!(
        FapiReturnCode,
        TSS2_FEATURE_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_error_trait_impl!(
        EsapiReturnCode,
        TSS2_ESYS_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_error_trait_impl!(SapiReturnCode, TSS2_SYS_RC_LAYER, TSS2_BASE_RC_BAD_SEQUENCE);
    test_error_trait_impl!(
        MuapiReturnCode,
        TSS2_MU_RC_LAYER,
        TSS2_BASE_RC_BAD_REFERENCE
    );
    test_error_trait_impl!(
        TctiReturnCode,
        TSS2_TCTI_RC_LAYER,
        TSS2_BASE_RC_BAD_REFERENCE
    );
    test_error_trait_impl!(
        BaseReturnCode,
        TSS2_RESMGR_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_error_trait_impl!(
        TpmResponseCode,
        TSS2_RESMGR_TPM_RC_LAYER,
        TPM2_RC_INITIALIZE
    );
}

macro_rules! test_display_trait_impl {
    ($expected_error_message:tt, $native_rc:ident, $tss_rc_layer:ident, $tss_rc:ident) => {
        let return_code = ReturnCode::try_from($tss_rc_layer | $tss_rc).unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} error in {} layer return code into a ReturnCode object.",
                std::stringify!($tss_rc),
                std::stringify!($tss_rc_layer)
            )
        });

        let response_code = $native_rc::try_from(u16::try_from($tss_rc).unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} into a u16 value.",
                std::stringify!($tss_rc)
            )
        }))
        .unwrap_or_else(|_| {
            panic!(
                "Failed to convert {} into a {}.",
                std::stringify!($tss_rc),
                std::any::type_name::<$native_rc>()
            )
        });

        assert_eq!(
            format!("{} {}", $expected_error_message, response_code),
            format!("{}", return_code)
        );
    };
}

#[test]
#[serial]
fn test_display_trait_implementation() {
    test_display_trait_impl!(
        "TSS Layer: TPM, Code: 0x00000100, Message:",
        TpmResponseCode,
        TSS2_TPM_RC_LAYER,
        TPM2_RC_INITIALIZE
    );
    test_display_trait_impl!(
        "TSS Layer: FAPI, Code: 0x00060007, Message:",
        FapiReturnCode,
        TSS2_FEATURE_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_display_trait_impl!(
        "TSS Layer: ESAPI, Code: 0x00070007, Message:",
        EsapiReturnCode,
        TSS2_ESYS_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_display_trait_impl!(
        "TSS Layer: SAPI, Code: 0x00080007, Message:",
        SapiReturnCode,
        TSS2_SYS_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_display_trait_impl!(
        "TSS Layer: MUAPI, Code: 0x00090005, Message:",
        MuapiReturnCode,
        TSS2_MU_RC_LAYER,
        TSS2_BASE_RC_BAD_REFERENCE
    );
    test_display_trait_impl!(
        "TSS Layer: TCTI, Code: 0x000A0005, Message:",
        TctiReturnCode,
        TSS2_TCTI_RC_LAYER,
        TSS2_BASE_RC_BAD_REFERENCE
    );
    test_display_trait_impl!(
        "TSS Layer: RESOURCE MANAGER, Code: 0x000B0007, Message:",
        BaseReturnCode,
        TSS2_RESMGR_RC_LAYER,
        TSS2_BASE_RC_BAD_SEQUENCE
    );
    test_display_trait_impl!(
        "TSS Layer: TPM RESOURCE MANAGER, Code: 0x000C0100, Message:",
        TpmResponseCode,
        TSS2_RESMGR_TPM_RC_LAYER,
        TPM2_RC_INITIALIZE
    );
}
