// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::{env, str::FromStr};
use tss_esapi::abstraction::ek;
use tss_esapi::constants::response_code::{FormatOneResponseCode, Tss2ResponseCode};
use tss_esapi::Error;
use tss_esapi::{constants::algorithm::AsymmetricAlgorithm, Context, Tcti};

pub fn create_ctx_without_session() -> Context {
    let tcti = match env::var("TEST_TCTI") {
        Err(_) => Tcti::Mssim(Default::default()),
        Ok(tctistr) => Tcti::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    };
    unsafe { Context::new(tcti).unwrap() }
}

#[test]
fn test_retrieve_ek_pubcert() {
    let mut context = create_ctx_without_session();

    // The error 395 is for "handle could not be found" - this makes it that if the NV Index
    // did not exist (the test is run on a TPM without an endorsement cert), it still passes.
    match ek::retrieve_ek_pubcert(&mut context, AsymmetricAlgorithm::Rsa) {
        Ok(_) => (),
        Err(Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(395)))) => (),
        Err(e) => panic!(format!("Error was unexpected: {:?}", e)),
    };
    match ek::retrieve_ek_pubcert(&mut context, AsymmetricAlgorithm::Ecc) {
        Ok(_) => (),
        Err(Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(395)))) => (),
        Err(e) => panic!(format!("Error was unexpected: {:?}", e)),
    };
}

#[test]
fn test_create_ek() {
    let mut context = create_ctx_without_session();

    let _ = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa).unwrap();
    let _ = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Ecc).unwrap();
}
