// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::common::SwtpmSession;
use tss_esapi::tcti_ldr::TctiNameConf;

#[allow(dead_code)]
pub fn name_conf() -> (SwtpmSession, TctiNameConf) {
    let swtpm = SwtpmSession::new();
    let tcti = swtpm.tcti();
    (swtpm, tcti)
}

mod tcti_context_tests;
mod tcti_info_tests;
