// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{
        TPM2_RC_1, TPM2_RC_2, TPM2_RC_3, TPM2_RC_4, TPM2_RC_5, TPM2_RC_6, TPM2_RC_7, TPM2_RC_8,
        TPM2_RC_9, TPM2_RC_A, TPM2_RC_B, TPM2_RC_C, TPM2_RC_D, TPM2_RC_E, TPM2_RC_F, TPM2_RC_H,
        TPM2_RC_P, TPM2_RC_S,
    },
    error::ArgumentNumber,
};

const ARGUMENT_NUMBERS: [u16; 15] = [
    TPM2_RC_1 as u16,
    TPM2_RC_2 as u16,
    TPM2_RC_3 as u16,
    TPM2_RC_4 as u16,
    TPM2_RC_5 as u16,
    TPM2_RC_6 as u16,
    TPM2_RC_7 as u16,
    TPM2_RC_8 as u16,
    TPM2_RC_9 as u16,
    TPM2_RC_A as u16,
    TPM2_RC_B as u16,
    TPM2_RC_C as u16,
    TPM2_RC_D as u16,
    TPM2_RC_E as u16,
    TPM2_RC_F as u16,
];

#[test]
fn test_valid_parameter_conversions() {
    let parameter_values = (1u8..16u8).collect::<Vec<u8>>();

    // Test Parameters
    ARGUMENT_NUMBERS.iter().zip(parameter_values).for_each(|(&nr, val)| {
        // Ex:
        // TPM2_RC_1 || TPM_RC_P = 0x140
        // 0 0 0 1    0 1 |0 0    0 0 0 0
        //              P |---Error nr---|
        // Only bits 6 to 11 is parsed by ArgumentNumber.
        // P bit is set, indicating parameter argument.
        let return_code_argument_info: u16 = nr | (TPM2_RC_P as u16);
        let actual = u8::try_from(
            return_code_argument_info
                .checked_shr(6).expect("Failed to extract argument information.")
            )
            .map (ArgumentNumber::from)
            .unwrap_or_else(|_| panic!("Failed to convert argument information {return_code_argument_info:#b} to u8."));
        let expected = ArgumentNumber::Parameter(val);
        assert_eq!(
            expected,
            actual,
            "Performing `from` conversion return code {return_code_argument_info:#02X} did not produce the expected {} with value {val}",
            std::stringify!(ArgumentNumber::Parameter),
        );
    })
}

#[test]
fn test_valid_session_conversions() {
    let session_values = (1u8..7u8).collect::<Vec<u8>>();

    ARGUMENT_NUMBERS[0..7].iter().zip(session_values).for_each(|(&nr, val)| {
        // Ex:
        // TPM2_RC_1 || TPM_RC_S = 0x900
        // 1 0 0 1    0 0 |0 0    0 0 0 0
        // S            P |---Error nr---|
        // Only bits 6 to 11 is parsed by ArgumentNumber.
        // Session bit is set and P bit is clear, indicating session argument.
        let return_code_argument_info: u16 = nr | (TPM2_RC_S as u16);
        let actual = u8::try_from(
            return_code_argument_info
                .checked_shr(6)
                .expect("Failed to extract argument information."),
        )
        .map(ArgumentNumber::from)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to convert argument information {return_code_argument_info:#b} to u8."
            )
        });
        let expected = ArgumentNumber::Session(val);
        assert_eq!(
            expected,
            actual,
            "Performing `from` conversion return code {return_code_argument_info:#02X} did not produce the expected {} with value {val}",
            std::stringify!(ArgumentNumber::Session),
        );
    })
}

#[test]
fn test_valid_handle_conversions() {
    let handle_values = (1u8..7u8).collect::<Vec<u8>>();

    ARGUMENT_NUMBERS[0..7].iter().zip(handle_values).for_each(|(&nr, val)| {
        // Ex:
        // TPM2_RC_1 || TPM_RC_H = 0x800
        // 0 0 0 1    0 0 |0 0    0 0 0 0
        // S            P |---Error nr---|
        // Only bits 6 to 11 is parsed by ArgumentNumber.
        // Session bit is clear and P bit is clear, indicating handle argument.
        let return_code_argument_info: u16 = nr | (TPM2_RC_H as u16);
        let actual = u8::try_from(
            return_code_argument_info
                .checked_shr(6)
                .expect("Failed to extract argument information."),
        )
        .map(ArgumentNumber::from)
        .unwrap_or_else(|_| {
            panic!(
                "Failed to convert argument information {return_code_argument_info:#b} to u8.",
            )
        });
        let expected = ArgumentNumber::Handle(val);
        assert_eq!(
            expected,
            actual,
            "Performing `from` conversion return code {return_code_argument_info:#02X} did not produce the expected {} with value {val}",
            std::stringify!(ArgumentNumber::Handle)
        );
    })
}

#[test]
fn test_display_trait_implementation_for_parameters() {
    for val in 1u8..16u8 {
        assert_eq!(
            format!("associated with parameter number {val}"),
            format!("{}", ArgumentNumber::Parameter(val)),
            "{} with value {val} did not produce the expected error message",
            std::stringify!(ArgumentNumber::Parameter),
        );
    }
}

#[test]
fn test_display_trait_implementation_for_sessions() {
    for val in 1u8..7u8 {
        assert_eq!(
            format!("associated with session number {val}"),
            format!("{}", ArgumentNumber::Session(val)),
            "{} with value {val} did not produce the expected error message",
            std::stringify!(ArgumentNumber::Session),
        );
    }
}

#[test]
fn test_display_trait_implementation_for_handles() {
    for val in 1u8..7u8 {
        assert_eq!(
            format!("associated with handle number {val}"),
            format!("{}", ArgumentNumber::Handle(val)),
            "{} with value {val} did not produce the expected error message",
            std::stringify!(ArgumentNumber::Handle),
        );
    }
}
