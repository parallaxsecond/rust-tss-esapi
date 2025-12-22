// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use serial_test::serial;
use tss_esapi::tcti_ldr::TctiInfo;

#[test]
#[serial]
fn new_info() {
    let info = TctiInfo::get_info(crate::tcti_ldr_tests::name_conf()).unwrap();
    let _version = info.version();
    let _name = info.name();
    let _description = info.description();
    let _config_help = info.config_help();
}
