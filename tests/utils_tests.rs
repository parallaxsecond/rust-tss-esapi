// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::{env, str::FromStr};
use tss_esapi::{utils, Context, Tcti};

pub fn create_ctx_without_session() -> Context {
    let tcti = match env::var("TEST_TCTI") {
        Err(_) => Tcti::Mssim(Default::default()),
        Ok(tctistr) => Tcti::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    };
    unsafe { Context::new(tcti).unwrap() }
}

#[test]
fn get_tpm_vendor() {
    let mut context = create_ctx_without_session();

    utils::get_tpm_vendor(&mut context).unwrap();
}
