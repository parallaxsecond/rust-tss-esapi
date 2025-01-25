// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    abstraction::{ak, ek, AsymmetricAlgorithmSelection},
    attributes::SessionAttributesBuilder,
    constants::SessionType,
    handles::AuthHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        session_handles::PolicySession,
    },
    structures::{Digest, SymmetricDefinition},
    utils,
};

use elliptic_curve::PublicKey;
use rsa::RsaPublicKey;

use crate::common::create_ctx_without_session;

#[test]
fn test_credential_ecc() {
    let mut context = create_ctx_without_session();

    let ek_ecc = ek::create_ek_object(
        &mut context,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        None,
    )
    .unwrap();

    let (ek_pub, _, _) = context.read_public(ek_ecc).unwrap();

    let ak_res = ak::create_ak(
        &mut context,
        ek_ecc,
        HashingAlgorithm::Sha384,
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384),
        SignatureSchemeAlgorithm::EcDsa,
        None,
        None,
    )
    .unwrap();

    let ak_ecc = ak::load_ak(
        &mut context,
        ek_ecc,
        None,
        ak_res.out_private,
        ak_res.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(ak_ecc).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (credential_blob, secret) = utils::make_credential_ecc::<_, sha2::Sha256, aes::Aes128>(
        PublicKey::<p256::NistP256>::try_from(&ek_pub).unwrap(),
        &cred,
        key_name,
    )
    .expect("Create credential");

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
        .unwrap();

    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_2, session_attributes, session_attributes_mask)
        .expect("Failed to call tr_sess_set_attributes");

    let _ = context
        .execute_with_session(Some(session_1), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(session_2)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((Some(session_1), Some(session_2), None));
    let decrypted = context
        .activate_credential(ak_ecc, ek_ecc, credential_blob, secret)
        .unwrap();

    assert_eq!(expected, decrypted);

    context.flush_context(ek_ecc.into()).unwrap();
    context.flush_context(ak_ecc.into()).unwrap();
}

#[test]
fn test_credential_rsa() {
    let mut context = create_ctx_without_session();

    let ek_rsa = ek::create_ek_object(
        &mut context,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        None,
    )
    .unwrap();

    let (ek_pub, _, _) = context.read_public(ek_rsa).unwrap();

    let ak_res = ak::create_ak(
        &mut context,
        ek_rsa,
        HashingAlgorithm::Sha256,
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        SignatureSchemeAlgorithm::RsaPss,
        None,
        None,
    )
    .unwrap();

    let ak_rsa = ak::load_ak(
        &mut context,
        ek_rsa,
        None,
        ak_res.out_private,
        ak_res.out_public,
    )
    .unwrap();

    let (_, key_name, _) = context.read_public(ak_rsa).unwrap();
    let cred = vec![1, 2, 3, 4, 5];
    let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

    let (credential_blob, secret) = utils::make_credential_rsa::<sha2::Sha256, aes::Aes128>(
        &RsaPublicKey::try_from(&ek_pub).unwrap(),
        &cred,
        key_name,
    )
    .expect("Create credential");

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    let session_1 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
        .unwrap();

    let session_2 = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    context
        .tr_sess_set_attributes(session_2, session_attributes, session_attributes_mask)
        .expect("Failed to call tr_sess_set_attributes");

    let _ = context
        .execute_with_session(Some(session_1), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(session_2)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    context.set_sessions((Some(session_1), Some(session_2), None));
    let decrypted = context
        .activate_credential(ak_rsa, ek_rsa, credential_blob, secret)
        .unwrap();

    assert_eq!(expected, decrypted);

    context.flush_context(ek_rsa.into()).unwrap();
    context.flush_context(ak_rsa.into()).unwrap();
}
