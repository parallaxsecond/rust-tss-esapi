// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::nv,
    constants::{algorithm::AsymmetricAlgorithm, tss::*},
    handles::{AuthHandle, KeyHandle, NvIndexTpmHandle, TpmHandle},
    tss2_esys::{
        ESYS_TR_RH_ENDORSEMENT, TPM2B_ECC_PARAMETER, TPM2B_PUBLIC, TPM2B_PUBLIC_KEY_RSA,
        TPMS_ECC_PARMS, TPMS_ECC_POINT, TPMS_RSA_PARMS, TPMS_SCHEME_HASH, TPMT_ECC_SCHEME,
        TPMT_KDF_SCHEME, TPMT_RSA_SCHEME, TPMT_SYM_DEF_OBJECT, TPMU_ASYM_SCHEME, TPMU_SYM_KEY_BITS,
        TPMU_SYM_MODE,
    },
    utils::{ObjectAttributes, PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder},
    Context, Result,
};

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.4 (Low Range) for Windows compatibility
const RSA_2048_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00002;
const ECC_P256_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0000a;

// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Appendix B.3.3 and B.3.4
fn create_ek_public_from_default_template(alg: AsymmetricAlgorithm) -> Result<TPM2B_PUBLIC> {
    let mut obj_attrs = ObjectAttributes(0);
    obj_attrs.set_fixed_tpm(true);
    obj_attrs.set_st_clear(false);
    obj_attrs.set_fixed_parent(true);
    obj_attrs.set_sensitive_data_origin(true);
    obj_attrs.set_user_with_auth(false);
    obj_attrs.set_admin_with_policy(true);
    obj_attrs.set_no_da(false);
    obj_attrs.set_encrypted_duplication(false);
    obj_attrs.set_restricted(true);
    obj_attrs.set_decrypt(true);
    obj_attrs.set_sign_encrypt(false);

    // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
    // With 32 null-bytes attached, because of the type of with_auth_policy
    let authpolicy: [u8; 64] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    match alg {
        AsymmetricAlgorithm::Rsa => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::RsaDetail(TPMS_RSA_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_AES,
                    keyBits: TPMU_SYM_KEY_BITS { aes: 128 },
                    mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
                },
                scheme: TPMT_RSA_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: Default::default(),
                },
                keyBits: 2048,
                exponent: 0,
            }))
            .with_unique(PublicIdUnion::Rsa(Box::new(TPM2B_PUBLIC_KEY_RSA {
                size: 256,
                buffer: [0; 512],
            })))
            .build(),
        AsymmetricAlgorithm::Ecc => Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_ECC)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(32, authpolicy)
            .with_parms(PublicParmsUnion::EccDetail(TPMS_ECC_PARMS {
                symmetric: TPMT_SYM_DEF_OBJECT {
                    algorithm: TPM2_ALG_AES,
                    keyBits: TPMU_SYM_KEY_BITS { sym: 128 },
                    mode: TPMU_SYM_MODE { sym: TPM2_ALG_CFB },
                },
                scheme: TPMT_ECC_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: TPMU_ASYM_SCHEME {
                        anySig: TPMS_SCHEME_HASH {
                            hashAlg: TPM2_ALG_NULL,
                        },
                    },
                },
                curveID: TPM2_ECC_NIST_P256,
                kdf: TPMT_KDF_SCHEME {
                    scheme: TPM2_ALG_NULL,
                    details: Default::default(),
                },
            }))
            .with_unique(PublicIdUnion::Ecc(Box::new(TPMS_ECC_POINT {
                x: TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: [0; 128],
                },
                y: TPM2B_ECC_PARAMETER {
                    size: 32,
                    buffer: [0; 128],
                },
            })))
            .build(),
    }
}

/// Create the Endorsement Key object from the specification templates
pub fn create_ek_object(context: &mut Context, alg: AsymmetricAlgorithm) -> Result<KeyHandle> {
    let ek_public = create_ek_public_from_default_template(alg)?;

    context.execute_with_nullauth_session(|ctx| {
        ctx.create_primary_key(ESYS_TR_RH_ENDORSEMENT, &ek_public, None, None, None, &[])
    })
}

/// Retreive the Endorsement Key public certificate from the TPM
pub fn retrieve_ek_pubcert(context: &mut Context, alg: AsymmetricAlgorithm) -> Result<Vec<u8>> {
    let nv_idx = match alg {
        AsymmetricAlgorithm::Rsa => RSA_2048_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Ecc => ECC_P256_EK_CERTIFICATE_NV_INDEX,
    };

    let nv_idx = NvIndexTpmHandle::new(nv_idx).unwrap();

    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle =
        context.execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_auth_handle))?;
    let nv_auth_handle: AuthHandle = nv_auth_handle.into();

    context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
}
