// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::constants::{
    algorithm::{EllipticCurve, HashingAlgorithm},
    response_code::Tss2ResponseCodeKind,
};
use tss_esapi::{Error, WrapperErrorKind as ErrorKind};

use tss_esapi::structures::{Auth, Digest, PublicKeyRSA};
use tss_esapi::utils::{AsymSchemeUnion, PublicKey, Signature, SignatureData};
use tss_esapi::Tcti;
use tss_esapi::{
    abstraction::transient::{KeyParams, RsaExponent, TransientKeyContextBuilder},
    TransientKeyContext,
};

const HASH: [u8; 32] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2,
    0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78,
];

fn create_ctx() -> TransientKeyContext {
    unsafe {
        TransientKeyContextBuilder::new()
            .with_tcti(Tcti::Mssim(Default::default()))
            .build()
            .unwrap()
    }
}

#[test]
fn wrong_key_sizes() {
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim(Default::default()))
                .with_root_key_size(1023)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim(Default::default()))
                .with_root_key_size(1025)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim(Default::default()))
                .with_root_key_size(2047)
                .build()
                .unwrap_err()
        },
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
    assert_eq!(
        unsafe {
            TransientKeyContextBuilder::new()
                .with_tcti(Tcti::Mssim(Default::default()))
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
                .with_tcti(Tcti::Mssim(Default::default()))
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
fn load_bad_sized_keypair() {
    let mut ctx = create_ctx();
    assert_eq!(
        ctx.load_external_rsa(
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[0xCA, 0xFE, 0xBA, 0xBE],
            RsaExponent::default()
        )
        .unwrap_err(),
        Error::WrapperError(ErrorKind::WrongParamSize)
    );
}

#[test]
fn load_keypair_size_mismatch() {
    let mut ctx = create_ctx();
    let private_key: [u8; 1000] = [0; 1000];
    let public_key: [u8; 2048] = [0; 2048];
    assert_eq!(
        ctx.load_external_rsa(&private_key, &public_key, RsaExponent::default())
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
    let digest = Digest::try_from(vec![
        0x02, 0x2b, 0x26, 0xb1, 0xc3, 0x18, 0xdb, 0x73, 0x36, 0xef, 0x6f, 0x50, 0x9c, 0x35, 0xdd,
        0xaa, 0xe1, 0x3d, 0x21, 0xdf, 0x83, 0x68, 0x0f, 0x48, 0xae, 0x5d, 0x8a, 0x5d, 0x37, 0x3c,
        0xc1, 0x05,
    ])
    .unwrap();

    let signature = Signature {
        scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
        signature: SignatureData::RsaSignature(vec![
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
        ]),
    };

    let mut ctx = create_ctx();
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
    let _ = ctx
        .verify_signature(pub_key, digest, signature)
        .expect("the signature should be valid");
}

#[test]
fn verify_keypair() {
    let pub_key = vec![
        0xCD, 0x1A, 0xBA, 0xE5, 0xD7, 0x34, 0x34, 0x1A, 0xD3, 0x73, 0xBA, 0xE4, 0xF9, 0xEF, 0x46,
        0xB1, 0xCF, 0x69, 0x9D, 0x40, 0x54, 0xC8, 0x59, 0xB9, 0xC0, 0xF0, 0xC8, 0x11, 0xCA, 0x4D,
        0x7B, 0x1C, 0xB0, 0x3C, 0x66, 0xEA, 0x65, 0x51, 0x56, 0x63, 0x9B, 0x78, 0xC5, 0xDB, 0x2C,
        0x2F, 0xEA, 0x42, 0x43, 0x0F, 0x41, 0x7A, 0xB3, 0xD4, 0xAE, 0xE5, 0xF6, 0x3B, 0x88, 0x1D,
        0xD1, 0x06, 0xA3, 0xC6, 0x01, 0x05, 0xBC, 0x46, 0xBB, 0x18, 0xC7, 0xA7, 0x94, 0xA1, 0x7F,
        0x50, 0x39, 0x24, 0x05, 0x55, 0x1F, 0x77, 0x28, 0x7E, 0x61, 0xB5, 0xF7, 0x84, 0x35, 0x4C,
        0xD3, 0x51, 0x02, 0x1E, 0x18, 0x53, 0xB0, 0xCF, 0xD3, 0x47, 0x0D, 0x4C, 0xC9, 0xBD, 0x9E,
        0x39, 0x83, 0x6B, 0x83, 0xC1, 0xBE, 0x6B, 0xB2, 0x00, 0xFE, 0xF5, 0x67, 0x86, 0x40, 0x6E,
        0x8C, 0xD4, 0x5F, 0x73, 0xE4, 0xA9, 0xF5, 0x23,
    ];

    let priv_key = vec![
        0xF6, 0x94, 0x95, 0x35, 0x2F, 0x2A, 0xB5, 0x8D, 0xB8, 0x9A, 0x0A, 0x6D, 0xDB, 0x06, 0x0C,
        0xA0, 0xBA, 0xA5, 0xEC, 0x19, 0x0D, 0x1D, 0x61, 0xF0, 0xFA, 0xE3, 0x2C, 0xDF, 0xB7, 0x51,
        0x6F, 0xC9, 0xE4, 0x96, 0x8B, 0x5C, 0x49, 0x4C, 0x05, 0x7F, 0x35, 0xDF, 0xE6, 0x91, 0x36,
        0xFE, 0x35, 0x43, 0x4F, 0x0A, 0x3B, 0x89, 0x79, 0x55, 0x13, 0x47, 0xC4, 0x7A, 0x35, 0x7A,
        0xBA, 0xD0, 0xAD, 0x0B,
    ];

    let mut ctx = create_ctx();
    let _key_context = ctx
        .load_external_rsa(&priv_key, &pub_key, RsaExponent::default())
        .unwrap();
}

#[test]
fn sign_with_bad_auth() {
    let mut ctx = create_ctx();
    let (key, key_auth) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    let auth_value = key_auth.unwrap();
    let mut bad_auth_values = auth_value.value().to_vec();
    bad_auth_values[6..10].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    ctx.sign(
        key,
        Some(Auth::try_from(bad_auth_values).unwrap()),
        Digest::try_from(HASH.to_vec()).unwrap(),
    )
    .unwrap_err();
}

#[test]
fn sign_with_no_auth() {
    let mut ctx = create_ctx();
    let (key, _) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    ctx.sign(key, None, Digest::try_from(HASH.to_vec()).unwrap())
        .unwrap_err();
}

#[test]
fn encrypt_decrypt() {
    let mut ctx = create_ctx();
    let (key, auth) = ctx
        .create_key(
            KeyParams::RsaEncrypt {
                size: 2048,
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    let dec_key = key.clone();
    let message = vec![0x1, 0x2, 0x3];

    let ciphertext = ctx
        .rsa_encrypt(
            key,
            None,
            PublicKeyRSA::try_from(message.clone()).unwrap(),
            AsymSchemeUnion::RSAOAEP(HashingAlgorithm::Sha256),
            None,
        )
        .unwrap();
    assert_ne!(message, ciphertext.value());

    let plaintext = ctx
        .rsa_decrypt(
            dec_key,
            auth,
            ciphertext,
            AsymSchemeUnion::RSAOAEP(HashingAlgorithm::Sha256),
            None,
        )
        .unwrap();
    assert_eq!(message, plaintext.value());
}

#[test]
fn two_signatures_different_digest() {
    let mut ctx = create_ctx();
    let (key1, auth1) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    let (key2, auth2) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    let signature1 = ctx
        .sign(key1, auth1, Digest::try_from(HASH.to_vec()).unwrap())
        .unwrap();
    let signature2 = ctx
        .sign(key2, auth2, Digest::try_from(HASH.to_vec()).unwrap())
        .unwrap();

    assert!(signature1.signature != signature2.signature);
}

#[test]
fn verify_wrong_key() {
    let mut ctx = create_ctx();
    let (key1, auth1) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();
    let (key2, _) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();

    // Sign with the first key
    let signature = ctx
        .sign(key1, auth1, Digest::try_from(HASH.to_vec()).unwrap())
        .unwrap();

    // Import and verify with the second key
    let pub_key = ctx.read_public_key(key2).unwrap();
    let pub_key = match pub_key {
        PublicKey::Rsa(pub_key) => pub_key,
        _ => panic!("Got wrong type of key!"),
    };
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
    if let Error::Tss2Error(error) = ctx
        .verify_signature(pub_key, Digest::try_from(HASH.to_vec()).unwrap(), signature)
        .unwrap_err()
    {
        assert_eq!(error.kind(), Some(Tss2ResponseCodeKind::Signature));
    } else {
        panic!("The signature verification should have failed with an invalid signature error.");
    }
}
#[test]
fn verify_wrong_digest() {
    let mut ctx = create_ctx();
    let (key, auth) = ctx
        .create_key(
            KeyParams::RsaSign {
                size: 2048,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                pub_exponent: 0,
            },
            16,
        )
        .unwrap();

    let signature = ctx
        .sign(key.clone(), auth, Digest::try_from(HASH.to_vec()).unwrap())
        .unwrap();
    let pub_key = ctx.read_public_key(key).unwrap();
    let pub_key = match pub_key {
        PublicKey::Rsa(pub_key) => pub_key,
        _ => panic!("Got wrong type of key!"),
    };
    let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();

    let mut digest_values = HASH.to_vec();
    digest_values[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    if let Error::Tss2Error(error) = ctx
        .verify_signature(pub_key, Digest::try_from(digest_values).unwrap(), signature)
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
        let (key, auth) = ctx
            .create_key(
                KeyParams::RsaSign {
                    size: 2048,
                    scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
                    pub_exponent: 0,
                },
                16,
            )
            .unwrap();
        let signature = ctx
            .sign(key.clone(), auth, Digest::try_from(HASH.to_vec()).unwrap())
            .unwrap();
        let pub_key = ctx.read_public_key(key).unwrap();
        let pub_key = match pub_key {
            PublicKey::Rsa(pub_key) => pub_key,
            _ => panic!("Got wrong type of key!"),
        };
        let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
        let _ = ctx
            .verify_signature(pub_key, Digest::try_from(HASH.to_vec()).unwrap(), signature)
            .unwrap();
    }
}

#[test]
fn create_ecc_key() {
    let mut ctx = create_ctx();
    let _ = ctx
        .create_key(
            KeyParams::Ecc {
                curve: EllipticCurve::NistP256,
                scheme: AsymSchemeUnion::ECDSA(HashingAlgorithm::Sha256),
            },
            16,
        )
        .unwrap();
}

#[test]
fn create_ecc_key_rsa_scheme() {
    let mut ctx = create_ctx();
    let _ = ctx
        .create_key(
            KeyParams::Ecc {
                curve: EllipticCurve::NistP256,
                scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            },
            16,
        )
        .unwrap_err();
}

#[test]
fn create_ecc_key_decryption_scheme() {
    let mut ctx = create_ctx();
    let _ = ctx
        .create_key(
            KeyParams::Ecc {
                curve: EllipticCurve::NistP256,
                scheme: AsymSchemeUnion::ECDH(HashingAlgorithm::Sha256),
            },
            16,
        )
        .unwrap_err();
}

#[test]
fn full_ecc_test() {
    let mut ctx = create_ctx();
    for _ in 0..4 {
        let (key, auth) = ctx
            .create_key(
                KeyParams::Ecc {
                    curve: EllipticCurve::NistP256,
                    scheme: AsymSchemeUnion::ECDSA(HashingAlgorithm::Sha256),
                },
                16,
            )
            .unwrap();
        let signature = ctx
            .sign(key.clone(), auth, Digest::try_from(HASH.to_vec()).unwrap())
            .unwrap();
        let _pub_key = ctx.read_public_key(key.clone()).unwrap();
        let _ = ctx
            .verify_signature(key, Digest::try_from(HASH.to_vec()).unwrap(), signature)
            .unwrap();
    }
}
