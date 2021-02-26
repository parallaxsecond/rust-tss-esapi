// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{cipher::Cipher, IntoKeyCustomization, KeyCustomization},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{tss::*, SessionType},
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, SignatureScheme},
        session_handles::PolicySession,
    },
    structures::{Auth, CreateKeyResult, Private},
    tss2_esys::{
        TPM2B_PUBLIC, TPMS_ECC_PARMS, TPMS_RSA_PARMS, TPMS_SCHEME_HASH, TPMT_ECC_SCHEME,
        TPMT_KDF_SCHEME, TPMT_RSA_SCHEME, TPMT_SYM_DEF_OBJECT, TPMU_ASYM_SCHEME, TPMU_SYM_KEY_BITS,
        TPMU_SYM_MODE,
    },
    utils::{PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder},
    Context, Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

fn create_ak_public<IKC: IntoKeyCustomization>(
    key_alg: AsymmetricAlgorithm,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureScheme,
    key_customization: IKC,
) -> Result<TPM2B_PUBLIC> {
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
        AsymmetricAlgorithm::Rsa => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(hash_alg.into())
            .with_object_attributes(obj_attrs)
            .with_parms(PublicParmsUnion::RsaDetail(TPMS_RSA_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_NULL,
                    keyBits: TPMU_SYM_KEY_BITS { aes: 0 },
                    mode: TPMU_SYM_MODE { aes: TPM2_ALG_NULL },
                },
                scheme: TPMT_RSA_SCHEME {
                    scheme: sign_alg.into(),
                    details: TPMU_ASYM_SCHEME {
                        anySig: TPMS_SCHEME_HASH {
                            hashAlg: hash_alg.into(),
                        },
                    },
                },
                keyBits: 2048,
                exponent: 0,
            }))
            .with_unique(PublicIdUnion::Rsa(Box::new(Default::default()))),
        AsymmetricAlgorithm::Ecc => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_ECC)
            .with_name_alg(hash_alg.into())
            .with_object_attributes(obj_attrs)
            .with_parms(PublicParmsUnion::EccDetail(TPMS_ECC_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_NULL,
                    keyBits: TPMU_SYM_KEY_BITS { sym: 0 },
                    mode: TPMU_SYM_MODE { sym: TPM2_ALG_NULL },
                },
                scheme: TPMT_ECC_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: TPMU_ASYM_SCHEME {
                        anySig: TPMS_SCHEME_HASH {
                            hashAlg: hash_alg.into(),
                        },
                    },
                },
                curveID: TPM2_ECC_NIST_P256,
                kdf: TPMT_KDF_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: Default::default(),
                },
            }))
            .with_unique(PublicIdUnion::Ecc(Box::new(Default::default()))),
        AsymmetricAlgorithm::Null => {
            // TDOD: Figure out what to with Null.
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
    ak_auth_value: Option<&Auth>,
    private: Private,
    public: TPM2B_PUBLIC,
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
    sign_alg: SignatureScheme,
    ak_auth_value: Option<&Auth>,
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
                ctx.create(parent, &ak_pub, ak_auth_value, None, None, None)
            })
        },
    )
}
