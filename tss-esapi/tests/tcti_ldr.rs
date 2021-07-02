// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::str::FromStr;
use tss_esapi::tcti_ldr::{TctiContext, TctiInfo, TctiNameConf};

#[allow(dead_code)]
pub fn name_conf() -> TctiNameConf {
    match env::var("TEST_TCTI") {
        Err(_) => TctiNameConf::Mssim(Default::default()),
        Ok(tctistr) => TctiNameConf::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    }
}

#[test]
fn new_context() {
    let _context = TctiContext::initialize(name_conf()).unwrap();
}

#[test]
fn new_info() {
    let info = TctiInfo::get_info(name_conf()).unwrap();
    let _version = info.version();
    let _name = info.name();
    let _description = info.description();
    let _config_help = info.config_help();
}
