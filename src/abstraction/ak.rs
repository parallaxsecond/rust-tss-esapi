// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::{
        algorithm::{AsymmetricAlgorithm, Cipher, HashingAlgorithm, SignatureScheme},
        tss::*,
        types::session::SessionType,
    },
    handles::{AuthHandle, KeyHandle},
    structures::{Auth, CreateKeyResult, Private},
    tss2_esys::{
        TPM2B_PUBLIC, TPMS_ECC_PARMS, TPMS_RSA_PARMS, TPMS_SCHEME_HASH, TPMT_ECC_SCHEME,
        TPMT_KDF_SCHEME, TPMT_RSA_SCHEME, TPMT_SYM_DEF_OBJECT, TPMU_ASYM_SCHEME, TPMU_SYM_KEY_BITS,
        TPMU_SYM_MODE,
    },
    utils::{
        ObjectAttributes, PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder, TpmaSessionBuilder,
    },
    Context, Error, Result, WrapperErrorKind,
};

fn create_ak_public(
    key_alg: AsymmetricAlgorithm,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureScheme,
) -> Result<TPM2B_PUBLIC> {
    let mut obj_attrs = ObjectAttributes(0);
    obj_attrs.set_restricted(true);
    obj_attrs.set_user_with_auth(true);
    obj_attrs.set_sign_encrypt(true);
    obj_attrs.set_decrypt(false);
    obj_attrs.set_fixed_tpm(true);
    obj_attrs.set_fixed_parent(true);
    obj_attrs.set_sensitive_data_origin(true);

    match key_alg {
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
    }
    .build()
}

/// This loads an Attestation Key previously generated under the Endorsement hierarchy
pub fn load_ak(
    context: &mut Context,
    parent: KeyHandle,
    ak_auth_value: Option<&Auth>,
    private: Private,
    public: TPM2B_PUBLIC,
) -> Result<KeyHandle> {
    let session = match context.start_auth_session(
        None,
        None,
        None,
        SessionType::Policy,
        Cipher::aes_128_cfb(),
        HashingAlgorithm::Sha256,
    )? {
        Some(ses) => ses,
        None => return Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
    };
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(TPMA_SESSION_DECRYPT)
        .with_flag(TPMA_SESSION_ENCRYPT)
        .build();
    context.tr_sess_set_attributes(session, session_attr)?;

    let key_handle = context.execute_with_temporary_object(session.handle().into(), |ctx, _| {
        let _ = ctx.execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                session,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })?;

        ctx.execute_with_session(Some(session), |ctx| ctx.load(parent, private, public))
    })?;

    if let Some(ak_auth_value) = ak_auth_value {
        context.tr_set_auth(key_handle.into(), ak_auth_value)?;
    }

    Ok(key_handle)
}

/// This creates an Attestation Key in the Endorsement hierarchy
pub fn create_ak(
    context: &mut Context,
    parent: KeyHandle,
    hash_alg: HashingAlgorithm,
    sign_alg: SignatureScheme,
    ak_auth_value: Option<&Auth>,
) -> Result<CreateKeyResult> {
    let key_alg = sign_alg.get_key_alg();

    let ak_pub = create_ak_public(key_alg, hash_alg, sign_alg)?;

    let session = match context.start_auth_session(
        None,
        None,
        None,
        SessionType::Policy,
        Cipher::aes_128_cfb(),
        HashingAlgorithm::Sha256,
    )? {
        Some(ses) => ses,
        None => return Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
    };
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(TPMA_SESSION_DECRYPT)
        .with_flag(TPMA_SESSION_ENCRYPT)
        .build();
    context.tr_sess_set_attributes(session, session_attr)?;

    context.execute_with_temporary_object(session.handle().into(), |ctx, _| {
        let _ = ctx.execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                session,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })?;

        ctx.execute_with_session(Some(session), |ctx| {
            ctx.create_key(parent, &ak_pub, ak_auth_value, None, None, None)
        })
    })
}
