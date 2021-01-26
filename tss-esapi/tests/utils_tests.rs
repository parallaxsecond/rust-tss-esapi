// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::utils;

mod common;
use common::create_ctx_without_session;

#[test]
fn get_tpm_vendor() {
    let mut context = create_ctx_without_session();

    utils::get_tpm_vendor(&mut context).unwrap();
}
