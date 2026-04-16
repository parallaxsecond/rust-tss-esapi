// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::tcti_ldr::TctiContext;

#[test]
fn new_context() {
    let (_swtpm, name_conf) = crate::tcti_ldr_tests::name_conf();
    let _context = TctiContext::initialize(name_conf).unwrap();
}
