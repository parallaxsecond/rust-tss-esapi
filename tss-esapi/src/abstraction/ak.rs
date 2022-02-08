// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{cipher::Cipher, IntoKeyCustomization, KeyCustomization},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{AlgorithmIdentifier, SessionType},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{
            AsymmetricAlgorithm, EccSchemeAlgorithm, HashingAlgorithm, PublicAlgorithm,
            RsaSchemeAlgorithm, SignatureSchemeAlgorithm,
        },
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        session_handles::PolicySession,
    },
    structures::{
        Auth, CreateKeyResult, EccScheme, KeyDerivationFunctionScheme, Private, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
    Context, Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

fn create_ak_public<IKC: IntoKeyCustomization>(
    key_alg: AsymmetricAlgorithm,
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
        AsymmetricAlgorithm::Rsa => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(RsaScheme::create(
                        RsaSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                    )?)
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.restricted())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default()),
        AsymmetricAlgorithm::Ecc => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(hash_alg)
            .with_object_attributes(obj_attrs)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::Null)
                    .with_ecc_scheme(EccScheme::create(
                        EccSchemeAlgorithm::try_from(AlgorithmIdentifier::from(sign_alg))?,
                        Some(hash_alg),
                        Some(0),
                    )?)
                    .with_curve(EccCurve::NistP192)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()?,
            ),
        AsymmetricAlgorithm::Null => {
            // TODO: Figure out what to with Null.
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
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
    context.tr_sess_set_attributes(
        policy_auth_session,
        session_attributes,
        session_attributes_mask,
    )?;

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
    sign_alg: SignatureSchemeAlgorithm,
    ak_auth_value: Option<Auth>,
    key_customization: IKC,
) -> Result<CreateKeyResult> {
    let key_alg = AsymmetricAlgorithm::try_from(sign_alg).map_err(|e| {
        // sign_alg is either HMAC or Null.
        error!("Could not retrieve asymmetric algorithm for provided signature scheme");
        e
    })?;

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
    context.tr_sess_set_attributes(
        policy_auth_session,
        session_attributes,
        session_attributes_mask,
    )?;

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
