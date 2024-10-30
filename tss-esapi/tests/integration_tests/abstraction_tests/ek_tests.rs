// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    abstraction::{ek, AsymmetricAlgorithmSelection},
    constants::return_code::TpmFormatOneError,
    error::TpmResponseCode,
    interface_types::{ecc::EccCurve, key_bits::RsaKeyBits},
    Error, ReturnCode,
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
        Err(Error::TssError(ReturnCode::Tpm(TpmResponseCode::FormatOne(error)))) => {
            assert_eq!(error.error_number(), TpmFormatOneError::Handle)
        }
        Err(e) => panic!("Error was unexpected: {:?}", e),
    };
    match ek::retrieve_ek_pubcert(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
    ) {
        Ok(_) => (),
        Err(Error::TssError(ReturnCode::Tpm(TpmResponseCode::FormatOne(error)))) => {
            assert_eq!(error.error_number(), TpmFormatOneError::Handle)
        }
        Err(e) => panic!("Error was unexpected: {:?}", e),
    };
}

#[test]
fn test_create_ek_rsa() {
    // RSA key sizes currently supported by swtpm
    let supported_ek_sizes = vec![RsaKeyBits::Rsa2048, RsaKeyBits::Rsa3072];
    let mut context = create_ctx_without_session();

    for key_bits in supported_ek_sizes {
        let handle = ek::create_ek_object(
            &mut context,
            AsymmetricAlgorithmSelection::Rsa(key_bits),
            None,
        )
        .unwrap_or_else(|_| panic!("failed to create EK {:?}", key_bits));
        context.flush_context(handle.into()).unwrap();
    }
}

#[test]
fn test_create_ek_ecc() {
    // ECC curves currently supported by swtpm
    let supported_ek_curves = vec![EccCurve::NistP256, EccCurve::NistP384];
    let mut context = create_ctx_without_session();

    for curve in supported_ek_curves {
        let handle =
            ek::create_ek_object(&mut context, AsymmetricAlgorithmSelection::Ecc(curve), None)
                .unwrap_or_else(|_| panic!("failed to create EK {:?}", curve));
        context.flush_context(handle.into()).unwrap();
    }
}
