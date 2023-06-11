// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    abstraction::{ek, AsymmetricAlgorithmSelection},
    constants::response_code::{FormatOneResponseCode, Tss2ResponseCode},
    interface_types::{ecc::EccCurve, key_bits::RsaKeyBits},
    Error,
};

use crate::common::create_ctx_without_session;

#[test]
fn test_retrieve_ek_pubcert() {
    let mut context = create_ctx_without_session();

    // The error 395 is for "handle could not be found" - this makes it that if the NV Index
    // did not exist (the test is run on a TPM without an endorsement cert), it still passes.
    match ek::retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
    ) {
        Ok(_) => (),
        Err(Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(395)))) => (),
        Err(e) => panic!("Error was unexpected: {:?}", e),
    };
    match ek::retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
    ) {
        Ok(_) => (),
        Err(Error::Tss2Error(Tss2ResponseCode::FormatOne(FormatOneResponseCode(395)))) => (),
        Err(e) => panic!("Error was unexpected: {:?}", e),
    };
}

#[test]
fn test_create_ek() {
    let mut context = create_ctx_without_session();

    let _ = ek::create_ek_object(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();
    let _ = ek::create_ek_object(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        None,
    )
    .unwrap();
}
