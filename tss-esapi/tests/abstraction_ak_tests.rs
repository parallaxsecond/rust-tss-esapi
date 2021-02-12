// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::{TryFrom, TryInto};

use tss_esapi::{
    abstraction::{ak, cipher::Cipher, ek},
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::AuthHandle,
    interface_types::algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
    structures::{Auth, Digest},
};

mod common;
use common::create_ctx_without_session;

#[test]
fn test_create_ak_rsa_rsa() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa).unwrap();
    ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureScheme::RsaPss,
        None,
    )
    .unwrap();
}

#[test]
fn test_create_ak_rsa_ecc() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa).unwrap();
    if ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureScheme::Sm2,
        None,
    )
    .is_ok()
    {
        // We can't use unwrap_err because that requires Debug on the T
        panic!("Should have errored");
    }
}

#[test]
fn test_create_and_use_ak() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(&mut context, AsymmetricAlgorithm::Rsa).unwrap();
    let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
    let att_key = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        SignatureScheme::RsaPss,
        Some(&ak_auth),
    )
    .unwrap();

    let loaded_ak = ak::load_ak(
        &mut context,
        ek_rsa,
        Some(&ak_auth),
        att_key.out_private,
        att_key.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(loaded_ak).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (session_aastributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    context
        .tr_sess_set_attributes(
            session_1.unwrap(),
            session_aastributes,
            session_attributes_mask,
        )
        .unwrap();
    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    context
        .tr_sess_set_attributes(
            session_2.unwrap(),
            session_aastributes,
            session_attributes_mask,
        )
        .unwrap();

    let (credential_blob, secret) = context
        .execute_without_session(|ctx| {
            ctx.make_credential(ek_rsa, cred.try_into().unwrap(), key_name)
        })
        .unwrap();

    let _ = context
        .execute_with_session(session_1, |ctx| {
            ctx.policy_secret(
                session_2.unwrap(),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((session_1, session_2, None));

    let decrypted = context
        .activate_credential(loaded_ak, ek_rsa, credential_blob, secret)
        .unwrap();

    assert_eq!(expected, decrypted);
}
