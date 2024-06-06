// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{
        cipher::Cipher, AsymmetricAlgorithmSelection, IntoKeyCustomization, KeyCustomization,
    },
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{AlgorithmIdentifier, SessionType},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{
            EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
            SignatureSchemeAlgorithm,
        },
        session_handles::PolicySession,
    },
    structures::{
        Auth, CreateKeyResult, EccPoint, EccScheme, KeyDerivationFunctionScheme, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
    Context, Error, Result, WrapperErrorKind,
};
use std::convert::{TryFrom, TryInto};

fn create_ak_public<IKC: IntoKeyCustomization>(
    key_alg: AsymmetricAlgorithmSelection,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureSchemeAlgorithm,
    key_customization: IKC,
) -> Result<Public> {
    let key_customization = key_customization.into_key_customization();

    let obj_attrs_builder = ObjectAttributesBuilder::new()
        .with_restricted(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true);

    let obj_attrs = if let Some(ref k) = key_customization {
        k.attributes(obj_attrs_builder)
    } else {
        obj_attrs_builder
    }
    .build()?;

    let key_builder = match key_alg {
        AsymmetricAlgorithmSelection::Rsa(key_bits) => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::create(
                        RsaSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                    )?)
                    .with_key_bits(key_bits)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.restricted())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default()),
        AsymmetricAlgorithmSelection::Ecc(ecc_curve) => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_ecc_scheme(EccScheme::create(
                        EccSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                        if sign_alg == SignatureSchemeAlgorithm::EcDaa {
                            Some(0)
                        } else {
                            None
                        },
                    )?)
                    .with_curve(ecc_curve)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::default()),
    };

    let key_builder = if let Some(ref k) = key_customization {
        k.template(key_builder)
    } else {
        key_builder
    };

    key_builder.build()
}

/// This loads an Attestation Key previously generated under the Endorsement hierarchy
pub fn load_ak(
    context: &mut Context,
    parent: KeyHandle,
    ak_auth_value: Option<Auth>,
    private: Private,
    public: Public,
) -> Result<KeyHandle> {
    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            Cipher::aes_128_cfb().try_into()?,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| Error::local_error(WrapperErrorKind::WrongValueFromTpm))?;

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .or_else(|e| {
            context.flush_context(SessionHandle::from(policy_auth_session).into())?;
            Err(e)
        })?;

    let key_handle = context.execute_with_temporary_object(
        SessionHandle::from(policy_auth_session).into(),
        |ctx, _| {
            let _ = ctx.execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(policy_auth_session)?,
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                )
            })?;

            ctx.execute_with_session(Some(policy_auth_session), |ctx| {
                ctx.load(parent, private, public)
            })
        },
    )?;

    if let Some(ak_auth_value) = ak_auth_value {
        context.tr_set_auth(key_handle.into(), ak_auth_value)?;
    }

    Ok(key_handle)
}

/// This creates an Attestation Key in the Endorsement hierarchy
pub fn create_ak<IKC: IntoKeyCustomization>(
    context: &mut Context,
    parent: KeyHandle,
    hash_alg: HashingAlgorithm,
    key_alg: AsymmetricAlgorithmSelection,
    sign_alg: SignatureSchemeAlgorithm,
    ak_auth_value: Option<Auth>,
    key_customization: IKC,
) -> Result<CreateKeyResult> {
    let ak_pub = create_ak_public(key_alg, hash_alg, sign_alg, key_customization)?;

    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            Cipher::aes_128_cfb().try_into()?,
            HashingAlgorithm::Sha256,
        )?
        .ok_or_else(|| Error::local_error(WrapperErrorKind::WrongValueFromTpm))?;

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .or_else(|e| {
            context.flush_context(SessionHandle::from(policy_auth_session).into())?;
            Err(e)
        })?;

    context.execute_with_temporary_object(
        SessionHandle::from(policy_auth_session).into(),
        |ctx, _| {
            let _ = ctx.execute_with_nullauth_session(|ctx| {
                ctx.policy_secret(
                    PolicySession::try_from(policy_auth_session)?,
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                )
            })?;

            ctx.execute_with_session(Some(policy_auth_session), |ctx| {
                ctx.create(parent, ak_pub, ak_auth_value, None, None, None)
            })
        },
    )
}
