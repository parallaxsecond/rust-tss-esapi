// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    constants::CommandCode,
    structures::CommandCodeList,
    tss2_esys::{TPM2_CC, TPML_CC},
    Error, WrapperErrorKind,
};

use std::convert::TryInto;

#[test]
fn test_conversions() {
    let expected_command_codes = vec![
        CommandCode::ChangeEps,
        CommandCode::ChangePps,
        CommandCode::Clear,
    ];
    let mut command_code_list = CommandCodeList::new();
    for command_code in expected_command_codes.iter() {
        command_code_list
            .add(*command_code)
            .expect("Failed to add command code to command code list");
    }

    assert_eq!(
        expected_command_codes.len(),
        command_code_list.len(),
        "The created command code list did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(command_code_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual,
                "The created command code list did not contain the expected value"
            )
        });

    let tpml_cc: TPML_CC = command_code_list
        .clone()
        .try_into()
        .expect("Failed to convert CommandCodeList into TPML_CC");

    assert_eq!(
        expected_command_codes.len(),
        tpml_cc.count as usize,
        "The number count field in TPML_CC did not contain the expected value"
    );

    expected_command_codes
        .iter()
        .zip(tpml_cc.commandCodes[0..tpml_cc.count as usize].iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                TPM2_CC::from(*expected),
                *actual,
                "Command code missmatch between command codes in CommandCodeList and converted CommandCodeList"
            )
        });

    let converted_command_code_list: CommandCodeList = tpml_cc
        .try_into()
        .expect("Failed to convert TPML_CC to CommandCodeList");

    assert_eq!(
        expected_command_codes.len(),
        converted_command_code_list.len(),
        "The command code list converted from TPML_CC did not contain the expected number of elements"
    );

    expected_command_codes
        .iter()
        .zip(converted_command_code_list.as_ref().iter())
        .for_each(|(expected, actual)| {
            assert_eq!(
                expected, actual, "Command code in command code list converted from TPML_CC did not match the expected value"
            )
        });
}

#[test]
fn test_invalid_conversions() {
    let mut command_code_list = CommandCodeList::new();
    for _ in 0..CommandCodeList::MAX_SIZE {
        command_code_list
            .add(CommandCode::ChangeEps)
            .expect("Failed to command code to list");
    }

    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::WrongParamSize)),
        command_code_list.add(CommandCode::ChangeEps),
        "Adding more command codes to command code list then it supports did not produce the expected error"
    );
}
