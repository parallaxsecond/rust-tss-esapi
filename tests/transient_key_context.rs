// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::response_code::{
    Error, Error::Tss2Error, Tss2ResponseCodeKind, WrapperErrorKind as ErrorKind,
};
use tss_esapi::utils::{AsymSchemeUnion, Signature};
use tss_esapi::{abstraction::transient::TransientKeyContextBuilder, Tcti, TransientKeyContext};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

fn create_ctx() -> TransientKeyContext {
    unsafe {
        TransientKeyContextBuilder::new()
            .with_tcti(Tcti::Mssim)
            .build()
            .unwrap()
    }
}

#[test]
fn wrong_key_sizes() {
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim)
                .with_root_key_size(1023)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim)
                .with_root_key_size(1025)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim)
                .with_root_key_size(2047)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim)
                .with_root_key_size(2049)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
}

#[test]
fn wrong_auth_size() {
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim)
                .with_root_key_auth_size(33)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
}

#[test]
fn load_bad_sized_key() {
    let mut ctx = create_ctx();
    assert_eq!(
        ctx.load_external_rsa_public_key(&[0xDE, 0xAD, 0xBE, 0xEF])
            .unwrap_err(),
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
}

#[test]
fn verify() {
    let pub_key = vec![
        0x96, 0xDC, 0x72, 0x77, 0x49, 0x82, 0xFD, 0x2D, 0x06, 0x65, 0x8C, 0xE5, 0x3A, 0xCD, 0xED,
        0xBD, 0x50, 0xD7, 0x6F, 0x3B, 0xE5, 0x6A, 0x76, 0xED, 0x3E, 0xD8, 0xF9, 0x93, 0x40, 0x55,
        0x86, 0x6F, 0xBE, 0x76, 0x60, 0xD2, 0x03, 0x23, 0x59, 0x19, 0x8D, 0xFC, 0x51, 0x6A, 0x95,
        0xC8, 0x5D, 0x5A, 0x89, 0x4D, 0xE5, 0xEA, 0x44, 0x78, 0x29, 0x62, 0xDB, 0x3F, 0xF0, 0xF7,
        0x49, 0x15, 0xA5, 0xAE, 0x6D, 0x81, 0x8F, 0x06, 0x7B, 0x0B, 0x50, 0x7A, 0x2F, 0xEB, 0x00,
        0xB6, 0x12, 0xF3, 0x10, 0xAF, 0x4D, 0x4A, 0xA9, 0xD9, 0x81, 0xBB, 0x1E, 0x2B, 0xDF, 0xB9,
        0x33, 0x3D, 0xD6, 0xB7, 0x8D, 0x23, 0x7C, 0x7F, 0xE7, 0x12, 0x48, 0x4F, 0x26, 0x73, 0xAF,
        0x63, 0x51, 0xA9, 0xDB, 0xA4, 0xAB, 0xB7, 0x27, 0x00, 0xD7, 0x1C, 0xFC, 0x2F, 0x61, 0x2A,
        0xB9, 0x5B, 0x66, 0xA0, 0xE0, 0xD8, 0xF3, 0xD9,
    ];

    // "Les carottes sont cuites." hashed with SHA256
    let digest = vec![
        0x02, 0x2b, 0x26, 0xb1, 0xc3, 0x18, 0xdb, 0x73, 0x36, 0xef, 0x6f, 0x50, 0x9c, 0x35, 0xdd,
        0xaa, 0xe1, 0x3d, 0x21, 0xdf, 0x83, 0x68, 0x0f, 0x48, 0xae, 0x5d, 0x8a, 0x5d, 0x37, 0x3c,
        0xc1, 0x05,
    ];

    let signature = Signature {
        scheme: AsymSchemeUnion::RSASSA(tss_esapi::constants::TPM2_ALG_SHA256),
        signature: vec![
            0x8c, 0xf8, 0x87, 0x3a, 0xb2, 0x9a, 0x18, 0xf9, 0xe0, 0x2e, 0xb9, 0x2d, 0xe7, 0xc8,
            0x32, 0x12, 0xd6, 0xd9, 0x2d, 0x98, 0xec, 0x9e, 0x47, 0xb7, 0x5b, 0x26, 0x86, 0x9d,
            0xf5, 0xa2, 0x6b, 0x8b, 0x6f, 0x00, 0xd3, 0xbb, 0x68, 0x88, 0xe1, 0xad, 0xcf, 0x1c,
            0x09, 0x81, 0x91, 0xbf, 0xee, 0xce, 0x4f, 0xb5, 0x83, 0x3c, 0xf5, 0xb0, 0xfa, 0x68,
            0x69, 0xde, 0x7b, 0xe8, 0x49, 0x69, 0x40, 0xad, 0x90, 0xf1, 0x7f, 0x31, 0xf2, 0x75,
            0x4e, 0x1c, 0x52, 0x92, 0x72, 0x2e, 0x0b, 0x06, 0xe7, 0x32, 0xb4, 0x5e, 0x82, 0x8b,
            0x39, 0x72, 0x24, 0x5f, 0xee, 0x17, 0xae, 0x2d, 0x77, 0x53, 0xff, 0x1a, 0xad, 0x12,
            0x83, 0x4f, 0xb5, 0x52, 0x92, 0x6e, 0xda, 0xb2, 0x55, 0x77, 0xa7, 0x58, 0xcc, 0x10,
            0xa6, 0x7f, 0xc5, 0x26, 0x4e, 0x5b, 0x75, 0x9d, 0x83, 0x05, 0x9f, 0x99, 0xde, 0xc6,
            0xf5, 0x12,
        ],
    };

    let mut ctx = create_ctx();
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
    let _ = ctx
        .verify_signature(pub_key, &digest, signature)
        .expect("the signature should be valid");
}

#[test]
fn sign_with_bad_auth() {
    let mut ctx = create_ctx();
    let (key, mut auth) = ctx.create_rsa_signing_key(2048, 16).unwrap();
    auth[6] = 0xDE;
    auth[7] = 0xAD;
    auth[8] = 0xBE;
    auth[9] = 0xEF;
    ctx.sign(key, &auth, &HASH).unwrap_err();
}

#[test]
fn sign_with_no_auth() {
    let mut ctx = create_ctx();
    let (key, _) = ctx.create_rsa_signing_key(2048, 16).unwrap();
    ctx.sign(key, &[], &HASH).unwrap_err();
}

#[test]
fn two_signatures_different_digest() {
    let mut ctx = create_ctx();
    let (key1, auth1) = ctx.create_rsa_signing_key(2048, 16).unwrap();
    let (key2, auth2) = ctx.create_rsa_signing_key(2048, 16).unwrap();
    let signature1 = ctx.sign(key1, &auth1, &HASH).unwrap();
    let signature2 = ctx.sign(key2, &auth2, &HASH).unwrap();

    assert!(signature1.signature != signature2.signature);
}

#[test]
fn verify_wrong_key() {
    let mut ctx = create_ctx();
    let (key1, auth1) = ctx.create_rsa_signing_key(2048, 16).unwrap();
    let (key2, _) = ctx.create_rsa_signing_key(2048, 16).unwrap();

    // Sign with the first key
    let signature = ctx.sign(key1, &auth1, &HASH).unwrap();

    // Import and verify with the second key
    let pub_key = ctx.read_public_key(key2).unwrap();
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
    if let Tss2Error(error) = ctx.verify_signature(pub_key, &HASH, signature).unwrap_err() {
        assert_eq!(error.kind(), Some(Tss2ResponseCodeKind::Signature));
    } else {
        panic!("The signature verification should have failed with an invalid signature error.");
    }
}
#[test]
fn verify_wrong_digest() {
    let mut ctx = create_ctx();
    let (key, auth) = ctx.create_rsa_signing_key(2048, 16).unwrap();

    let signature = ctx.sign(key.clone(), &auth, &HASH).unwrap();
    let pub_key = ctx.read_public_key(key).unwrap();
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();

    let mut digest_copy = HASH.to_vec();
    digest_copy[0] = 0xDE;
    digest_copy[1] = 0xAD;
    digest_copy[2] = 0xBE;
    digest_copy[3] = 0xEF;
    if let Tss2Error(error) = ctx
        .verify_signature(pub_key, &digest_copy, signature)
        .unwrap_err()
    {
        assert_eq!(error.kind(), Some(Tss2ResponseCodeKind::Signature));
    } else {
        panic!("The signature verification should have failed with an invalid signature error.");
    }
}

#[test]
fn full_test() {
    let mut ctx = create_ctx();
    for _ in 0..4 {
        let (key, auth) = ctx.create_rsa_signing_key(2048, 16).unwrap();
        let signature = ctx.sign(key.clone(), &auth, &HASH).unwrap();
        let pub_key = ctx.read_public_key(key).unwrap();
        let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
        let _ = ctx.verify_signature(pub_key, &HASH, signature).unwrap();
    }
}
