// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use serial_test::serial;
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        return_code::ReturnCodeLayer,
        tss::{
            TSS2_ESYS_RC_LAYER, TSS2_FEATURE_RC_LAYER, TSS2_MU_RC_LAYER, TSS2_RESMGR_RC_LAYER,
            TSS2_RESMGR_TPM_RC_LAYER, TSS2_SYS_RC_LAYER, TSS2_TCTI_RC_LAYER, TSS2_TPM_RC_LAYER,
        },
    },
    tss2_esys::TSS2_RC_LAYER_SHIFT,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_layer:ident, $return_code_layer:ident) => {
        let tss_rc_layer_unshifted = u8::try_from(
            $tss_rc_layer
                .checked_shr(TSS2_RC_LAYER_SHIFT)
                .expect("Failed to shift layer value using TSS2_RC_LAYER_SHIFT"),
        )
        .expect(&format!(
            "Failed to convert shifted {} value to u8",
            std::stringify!($tss_rc_layer)
        ));

        assert_eq!(
            tss_rc_layer_unshifted,
            u8::from(ReturnCodeLayer::$return_code_layer),
            "Conversion of {} into TSS_RC did not result in the expected {}",
            std::stringify!(ReturnCodeLayer::$return_code_layer),
            std::stringify!($tss_rc_layer)
        );
        assert_eq!(
            ReturnCodeLayer::$return_code_layer,
            ReturnCodeLayer::try_from(tss_rc_layer_unshifted).expect(&format!(
                "Failed to convert the shifted u8 for {} value to ReturnCodeLayer",
                std::stringify!($tss_rc_layer)
            )),
            "Conversion of {} to ReturnCodeLayer did not result in the expected {}",
            std::stringify!($tss_rc_layer),
            std::stringify!(ReturnCodeLayer::$return_code_layer)
        );
    };
}
#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_TPM_RC_LAYER, Tpm);
    test_valid_conversion!(TSS2_FEATURE_RC_LAYER, Feature);
    test_valid_conversion!(TSS2_ESYS_RC_LAYER, Esys);
    test_valid_conversion!(TSS2_SYS_RC_LAYER, Sys);
    test_valid_conversion!(TSS2_MU_RC_LAYER, Mu);
    test_valid_conversion!(TSS2_TCTI_RC_LAYER, Tcti);
    test_valid_conversion!(TSS2_RESMGR_RC_LAYER, ResMgr);
    test_valid_conversion!(TSS2_RESMGR_TPM_RC_LAYER, ResMgrTpm);
}

#[test]
fn test_invalid_conversion() {
    let valid_values: [u8; 8] = [
        ReturnCodeLayer::Tpm.into(),
        ReturnCodeLayer::Feature.into(),
        ReturnCodeLayer::Esys.into(),
        ReturnCodeLayer::Sys.into(),
        ReturnCodeLayer::Mu.into(),
        ReturnCodeLayer::Tcti.into(),
        ReturnCodeLayer::ResMgr.into(),
        ReturnCodeLayer::ResMgrTpm.into(),
    ];
    for item in 0..u8::MAX {
        if !valid_values.contains(&item) {
            assert_eq!(
                Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
                ReturnCodeLayer::try_from(item),
                "Converting an invalid value {item} into ReturnCodeLayer did not result in the expected error"
            );
        }
    }
}
