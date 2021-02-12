// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_create {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_create() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let _ = context
            .create(
                prim_key_handle,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap();
    }
}

mod test_load {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_load() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let result = context
            .create(
                prim_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap();

        let _ = context
            .load(prim_key_handle, result.out_private, result.out_public)
            .unwrap();
    }
}

mod test_load_external_public {
    use crate::common::{create_ctx_with_session, KEY};
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        constants::tss::{TPM2_ALG_RSA, TPM2_ALG_SHA256},
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        tss2_esys::{TPM2B_PUBLIC, TPM2B_PUBLIC_KEY_RSA},
        utils::{
            AsymSchemeUnion, PublicIdUnion, PublicParmsUnion, Tpm2BPublicBuilder,
            TpmsRsaParmsBuilder,
        },
    };

    pub fn get_ext_rsa_pub() -> TPM2B_PUBLIC {
        let scheme = AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256);
        let rsa_parms = TpmsRsaParmsBuilder::new_unrestricted_signing_key(scheme, 2048, 0)
            .build()
            .unwrap(); // should not fail as we control the params

        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

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
    fn test_load_external_public() {
        let mut context = create_ctx_with_session();
        let pub_key = get_ext_rsa_pub();

        context
            .load_external_public(&pub_key, Hierarchy::Owner)
            .unwrap();
    }
}

mod test_read_public {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::Auth};

    #[test]
    fn test_read_public() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_make_credential {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::TryInto;
    use tss_esapi::interface_types::resource_handles::Hierarchy;

    #[test]
    fn test_make_credential() {
        let mut context = create_ctx_with_session();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (_, key_name, _) = context.read_public(key_handle).unwrap();

        let cred = vec![1, 2, 3, 4, 5];

        context
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, cred.try_into().unwrap(), key_name)
            })
            .unwrap();
    }
}

mod test_activate_credential {
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        abstraction::cipher::Cipher,
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::Digest,
    };
    #[test]
    fn test_make_activate_credential() {
        let mut context = create_ctx_with_session();

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

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
                session_attributes,
                session_attributes_mask,
            )
            .unwrap();
        let session_2 = context
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
                session_2.unwrap(),
                session_attributes,
                session_attributes_mask,
            )
            .unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (_, key_name, _) = context.read_public(key_handle).unwrap();

        let cred = vec![1, 2, 3, 4, 5];

        let (credential_blob, secret) = context
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, cred.try_into().unwrap(), key_name)
            })
            .unwrap();

        context.set_sessions((session_1, session_2, None));

        let decrypted = context
            .activate_credential(key_handle, key_handle, credential_blob, secret)
            .unwrap();

        let expected = Digest::try_from(vec![1, 2, 3, 4, 5]).unwrap();

        assert_eq!(expected, decrypted);
    }
}

mod test_unseal {
    use crate::common::{create_ctx_with_session, create_public_sealed_object, decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::resource_handles::Hierarchy, structures::SensitiveData};

    #[test]
    fn unseal() {
        let testbytes: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x42];

        let mut context = create_ctx_with_session();

        let key_handle_seal = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let key_handle_unseal = context
            .create_primary(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let key_pub = create_public_sealed_object();
        let result = context
            .create(
                key_handle_seal,
                &key_pub,
                None,
                Some(SensitiveData::try_from(testbytes.to_vec()).unwrap()).as_ref(),
                None,
                None,
            )
            .unwrap();
        let loaded_key = context
            .load(key_handle_unseal, result.out_private, result.out_public)
            .unwrap();
        let unsealed = context.unseal(loaded_key.into()).unwrap();
        let unsealed = unsealed.value();
        assert!(unsealed == testbytes);
    }
}
