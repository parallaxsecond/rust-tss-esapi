// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

const HASH: [u8; 64] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0x69,
    0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2, 0x94,
    0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0xA2, 0x94, 0x8E,
    0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78, 0x37, 0x78,
];

const KEY: [u8; 512] = [
    231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71, 185, 1,
    209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140, 23, 139, 169, 15,
    193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248, 250, 100, 115, 214, 166,
    165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45, 8, 9, 36, 202, 171, 165, 43, 208,
    186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49, 214, 235, 151, 9, 189, 174,
    144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205, 54, 9, 181, 14, 35, 246, 49,
    150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18, 223, 179, 229, 0, 204, 65, 69, 166, 180,
    11, 49, 131, 96, 163, 96, 158, 7, 109, 119, 208, 17, 237, 125, 187, 121, 94, 65, 2, 86, 105,
    68, 51, 197, 73, 108, 185, 231, 126, 199, 81, 1, 251, 211, 45, 47, 15, 113, 135, 197, 152, 239,
    180, 111, 18, 192, 136, 222, 11, 99, 41, 248, 205, 253, 209, 56, 214, 32, 225, 3, 49, 161, 58,
    57, 190, 69, 86, 95, 185, 184, 155, 76, 8, 122, 104, 81, 222, 234, 246, 40, 98, 182, 90, 160,
    111, 74, 102, 36, 148, 99, 69, 207, 214, 104, 87, 128, 238, 26, 121, 107, 166, 4, 64, 5, 210,
    164, 162, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

use std::convert::TryInto;
use tss_esapi::constants::*;
use tss_esapi::tss2_esys::*;
use tss_esapi::utils::{
    self, algorithm_specifiers::Cipher, AsymSchemeUnion, ObjectAttributes, PublicIdUnion,
    PublicParmsUnion, Signature, Tpm2BPublicBuilder, TpmaSessionBuilder, TpmsRsaParmsBuilder,
    TpmtSymDefBuilder,
};
use tss_esapi::*;

fn create_ctx_with_session() -> Context {
    let mut ctx = unsafe { Context::new(Tcti::Mssim).unwrap() };
    let session = ctx
        .start_auth_session(
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &[],
            TPM2_SE_HMAC,
            utils::TpmtSymDefBuilder::aes_256_cfb(),
            TPM2_ALG_SHA256,
        )
        .unwrap();
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(TPMA_SESSION_DECRYPT)
        .with_flag(TPMA_SESSION_ENCRYPT)
        .build();
    ctx.tr_sess_set_attributes(session, session_attr).unwrap();
    ctx.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));

    ctx
}

fn create_ctx_without_session() -> Context {
    unsafe { Context::new(Tcti::Mssim).unwrap() }
}

#[test]
fn comprehensive_test() {
    env_logger::init();

    let mut context = create_ctx_with_session();
    let key_auth: Vec<u8> = context.get_random(16).unwrap();

    let prim_key_handle = context
        .create_primary_key(
            ESYS_TR_RH_OWNER,
            &utils::get_rsa_public(true, true, false, 2048),
            &key_auth,
            &[],
            &[],
            &[],
        )
        .unwrap();

    let new_session = context
        .start_auth_session(
            ESYS_TR_NONE,
            prim_key_handle,
            &[],
            TPM2_SE_HMAC,
            utils::TpmtSymDefBuilder::aes_256_cfb(),
            TPM2_ALG_SHA256,
        )
        .unwrap();
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(TPMA_SESSION_DECRYPT)
        .with_flag(TPMA_SESSION_ENCRYPT)
        .build();
    context
        .tr_sess_set_attributes(new_session, session_attr)
        .unwrap();
    context.set_sessions((new_session, ESYS_TR_NONE, ESYS_TR_NONE));

    let (key_priv, key_pub) = context
        .create_key(
            prim_key_handle,
            &utils::get_rsa_public(false, false, true, 1024),
            &key_auth,
            &[],
            &[],
            &[],
        )
        .unwrap();
    let key_handle = context.load(prim_key_handle, key_priv, key_pub).unwrap();

    let key_context = context.context_save(key_handle).unwrap();
    let key_handle = context.context_load(key_context).unwrap();
    context.tr_set_auth(key_handle, &key_auth).unwrap();
    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL,
        details: Default::default(),
    };
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    let signature = context
        .sign(key_handle, &HASH[..32], scheme, &validation)
        .unwrap();
    context
        .verify_signature(key_handle, &HASH[..32], &signature.try_into().unwrap())
        .unwrap();
}

mod test_start_sess {
    use super::*;

    #[test]
    fn test_simple_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
    }

    #[test]
    fn test_nonce_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[
                    128, 85, 22, 124, 85, 9, 12, 55, 23, 73, 1, 244, 102, 44, 95, 39, 10,
                ],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
    }

    #[test]
    fn test_long_nonce_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[
                    231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5,
                    222, 71, 185, 1, 209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198,
                    245, 210, 140, 23, 139, 169, 15, 193, 4, 145, 52, 138, 149, 155, 238, 36, 74,
                    152, 179, 108, 200, 248, 250, 100, 115, 214, 166, 165, 1, 27, 51, 11, 11, 244,
                    218, 157, 3, 174, 171, 142, 45, 8, 9, 36, 202, 171, 165, 43, 208, 186, 232, 15,
                    241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49, 214, 235, 151, 9, 189,
                    174, 144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205, 54, 9,
                    181, 14, 35, 246, 49, 150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18,
                    223,
                ],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap_err();
    }

    #[test]
    fn test_bound_sess() {
        let mut context = create_ctx_with_session();
        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[],
                &[],
                &[],
            )
            .unwrap();

        context
            .start_auth_session(
                prim_key_handle,
                prim_key_handle,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
    }

    #[test]
    fn test_encrypted_start_sess() {
        let mut context = create_ctx_without_session();
        let encrypted_sess = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(encrypted_sess, session_attr)
            .unwrap();

        let _ = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
    }

    #[test]
    fn test_authenticated_start_sess() {
        let mut context = create_ctx_without_session();
        let auth_sess = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
        context.set_sessions((auth_sess, ESYS_TR_NONE, ESYS_TR_NONE));

        context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap_err();
    }
}

mod test_pcr_read {
    use super::*;

    #[test]
    fn test_pcr_read_command() {
        let mut context = create_ctx_without_session();
        // Read PCR 0
        let mut selection = TPML_PCR_SELECTION {
            count: 0,
            pcrSelections: Default::default(),
        };

        selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
        selection.pcrSelections[0].sizeofSelect = 1;
        selection.pcrSelections[0].pcrSelect[0] = 0x01; // Only pcr 0.

        let _ = context.pcr_read(&selection).unwrap();
    }
}

mod test_get_random {
    use super::*;

    #[test]
    fn test_encrypted_get_rand() {
        let mut context = create_ctx_with_session();
        let encrypted_sess = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(encrypted_sess, session_attr)
            .unwrap();

        context.set_sessions((encrypted_sess, ESYS_TR_NONE, ESYS_TR_NONE));
        let _ = context.get_random(10).unwrap();
    }

    #[test]
    fn test_authenticated_get_rand() {
        let mut context = create_ctx_with_session();
        let auth_sess = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();

        context.set_sessions((auth_sess, ESYS_TR_NONE, ESYS_TR_NONE));
        let _ = context.get_random(10).unwrap_err();
    }

    #[test]
    fn test_get_0_rand() {
        let mut context = create_ctx_with_session();
        let _ = context.get_random(0);
    }
}

mod test_create_primary {
    use super::*;

    #[test]
    fn test_create_primary() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
        assert!(key_handle != ESYS_TR_NONE);
    }

    #[test]
    fn test_long_auth_create_primary() {
        let mut context = create_ctx_with_session();

        let _ = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &[0xa5; 100],
                &[],
                &[],
                &[],
            )
            .unwrap_err();
    }

    #[test]
    fn test_long_init_data_create_primary() {
        let mut context = create_ctx_with_session();

        let _ = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[0xa5; 300],
                &[],
                &[],
            )
            .unwrap_err();
    }

    #[test]
    fn test_long_outside_info_create_primary() {
        let mut context = create_ctx_with_session();

        let _ = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[],
                &[0xfe; 80],
                &[],
            )
            .unwrap_err();
    }

    #[test]
    fn test_long_pcrs_create_primary() {
        let mut context = create_ctx_with_session();

        let _ = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[],
                &[],
                &[Default::default(); 20],
            )
            .unwrap_err();
    }
}

mod test_create {
    use super::*;

    #[test]
    fn test_create() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let (_, _) = context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
    }

    #[test]
    fn test_long_auth_create() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        assert!(context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(true, true, false, 2048),
                &[0xa5; 100],
                &[],
                &[],
                &[],
            )
            .is_err());
    }

    #[test]
    fn test_long_init_data_create() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        assert!(context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[0xa5; 300],
                &[],
                &[],
            )
            .is_err());
    }

    #[test]
    fn test_long_outside_info_create() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        assert!(context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[],
                &[0xfe; 80],
                &[],
            )
            .is_err());
    }

    #[test]
    fn test_long_pcrs_create() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        assert!(context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(true, true, false, 2048),
                &[],
                &[],
                &[],
                &[Default::default(); 20],
            )
            .is_err());
    }
}

mod test_load {
    use super::*;

    #[test]
    fn test_load() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let (private, public) = context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let _ = context.load(prim_key_handle, private, public).unwrap();
    }
}

mod test_sign {
    use super::*;

    #[test]
    fn test_sign() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(key_handle, &HASH[..32], scheme, &validation)
            .unwrap();
    }

    #[test]
    fn test_sign_empty_digest() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(key_handle, &[], scheme, &validation)
            .unwrap_err();
    }

    #[test]
    fn test_sign_large_digest() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(key_handle, &[0xbb; 40], scheme, &validation)
            .unwrap_err();
    }
}

mod test_verify_sig {
    use super::*;

    #[test]
    fn test_verify_sig() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = context
            .sign(key_handle, &HASH[..32], scheme, &validation)
            .unwrap();

        context
            .verify_signature(key_handle, &HASH[..32], &signature.try_into().unwrap())
            .unwrap();
    }

    #[test]
    fn test_verify_wrong_sig() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let mut signature = context
            .sign(key_handle, &HASH[..32], scheme, &validation)
            .unwrap();

        signature.signature.reverse();
        assert!(context
            .verify_signature(key_handle, &HASH[..32], &signature.try_into().unwrap())
            .is_err());
    }

    #[test]
    fn test_verify_wrong_sig_2() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256),
            signature: vec![0xab; 500],
        };
        assert!(context
            .verify_signature(key_handle, &HASH[..32], &signature.try_into().unwrap())
            .is_err());
    }

    #[test]
    fn test_verify_wrong_sig_3() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256),
            signature: vec![0; 0],
        };
        assert!(context
            .verify_signature(key_handle, &HASH[..32], &signature.try_into().unwrap())
            .is_err());
    }
}

mod test_load_ext {
    use super::*;

    pub fn get_ext_rsa_pub() -> TPM2B_PUBLIC {
        let symmetric = TpmtSymDefBuilder::aes_256_cfb_object();
        let scheme = AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256);
        let rsa_parms = TpmsRsaParmsBuilder::new()
            .with_symmetric(symmetric)
            .with_key_bits(2048)
            .with_scheme(scheme)
            .build()
            .unwrap(); // should not fail as we control the params
        let mut object_attributes = ObjectAttributes(0);
        object_attributes.set_user_with_auth(true);
        object_attributes.set_decrypt(false);
        object_attributes.set_sign_encrypt(true);
        object_attributes.set_restricted(false);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: 256,
            buffer: KEY,
        };
        let pub_key = PublicIdUnion::Rsa(Box::from(pub_buffer));

        Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(object_attributes)
            .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
            .with_unique(pub_key)
            .build()
            .unwrap() // should not fail as we control the params
    }

    #[test]
    fn test_load_ext_pub() {
        let mut context = create_ctx_with_session();
        let pub_key = get_ext_rsa_pub();

        context
            .load_external_public(&pub_key, TPM2_RH_OWNER)
            .unwrap();
    }
}

mod test_read_pub {
    use super::*;

    #[test]
    fn test_read_pub() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_flush_context {
    use super::*;

    #[test]
    fn test_flush_ctx() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
        context.flush_context(key_handle).unwrap();
        assert!(context.read_public(key_handle).is_err());
    }

    #[test]
    fn test_flush_parent_ctx() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let (private, public) = context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_ctx_save {
    use super::*;

    #[test]
    fn test_ctx_save() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
        let _ = context.context_save(key_handle).unwrap();
    }

    #[test]
    fn test_ctx_save_leaf() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let (private, public) = context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle).unwrap();
        let _ = context.context_save(key_handle).unwrap();
    }
}

mod test_ctx_load {
    use super::*;

    #[test]
    fn test_ctx_load() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let (private, public) = context
            .create_key(
                prim_key_handle,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle).unwrap();
        let key_ctx = context.context_save(key_handle).unwrap();
        let key_handle = context.context_load(key_ctx).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_handle_auth {
    use super::*;

    #[test]
    fn test_set_handle_auth() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        let key_ctx = context.context_save(prim_key_handle).unwrap();
        context.flush_context(prim_key_handle).unwrap();
        let new_key_handle = context.context_load(key_ctx).unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        context.tr_set_auth(new_key_handle, &key_auth).unwrap();
        let _ = context
            .sign(new_key_handle, &HASH[..32], scheme, &validation)
            .unwrap();
    }

    #[test]
    fn test_set_large_handle() {
        let mut context = create_ctx_with_session();
        let key_auth: Vec<u8> = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(false, false, true, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        context
            .tr_set_auth(prim_key_handle, &[0xff; 100])
            .unwrap_err();
    }

    // Test is ignored as the current version of the TSS library segfaults on the `set auth` call
    // with `ESYS_TR_NONE` as the handle.
    // See: https://github.com/tpm2-software/tpm2-tss/issues/1593
    #[ignore]
    #[test]
    fn test_invalid_handle() {
        let mut context = create_ctx_with_session();
        context.tr_set_auth(ESYS_TR_NONE, &[0x11; 10]).unwrap_err();
    }
}

mod test_session_attr {
    use super::*;

    #[test]
    fn test_session_attr() {
        let mut context = create_ctx_with_session();
        let sess_handle = context
            .start_auth_session(
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();

        let sess_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(sess_handle, sess_attr)
            .unwrap();
        context.set_sessions((sess_handle, ESYS_TR_NONE, ESYS_TR_NONE));

        let _ = context.get_random(10).unwrap();
    }
}

mod test_test_parms {
    use super::*;

    #[test]
    fn test_sym_parms() {
        let mut context = create_ctx_without_session();
        let cipher = Cipher::aes_256_cfb();
        context
            .test_parms(PublicParmsUnion::SymDetail(cipher))
            .unwrap();
    }
}
