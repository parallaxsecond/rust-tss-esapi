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
            .load(prim_key_handle, result.out_private, &result.out_public)
            .unwrap();
    }
}

mod test_load_external_public {
    use crate::common::{create_ctx_with_session, KEY};
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            resource_handles::Hierarchy,
        },
        structures::{Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme},
    };

    pub fn get_ext_rsa_pub() -> Public {
        let object_attributes = ObjectAttributesBuilder::new()
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new_unrestricted_signing_key(
                    RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                        .expect("Failed to create rsa scheme"),
                    RsaKeyBits::Rsa2048,
                    Default::default(),
                )
                .build()
                .expect("Failed to create rsa parameters for public structure"),
            )
            .with_rsa_unique_identifier(
                &PublicKeyRsa::try_from(&KEY[..256])
                    .expect("Failed to create Public RSA key from buffer"),
            )
            .build()
            .expect("Failed to build Public structure")
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
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Digest, SymmetricDefinition},
    };
    #[test]
    fn test_make_activate_credential() {
        let mut context = create_ctx_with_session();

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

        let session_1 = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
            .expect("session_1: Call to start_auth_session failed.")
            .expect("session_1: The auth session returned was NONE");
        context
            .tr_sess_set_attributes(session_1, session_attributes, session_attributes_mask)
            .expect("Call to tr_sess_set_attributes failed");
        let session_2 = context
            .execute_without_session(|ctx| {
                ctx.start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Hmac,
                    SymmetricDefinition::AES_256_CFB,
                    HashingAlgorithm::Sha256,
                )
            })
            .expect("session_2: Call to start_auth_session failed.")
            .expect("session_2: The auth session returned was NONE");
        context
            .tr_sess_set_attributes(session_2, session_attributes, session_attributes_mask)
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

        let (_, key_name, _) = context
            .read_public(key_handle)
            .expect("Call to read_public failed");

        let cred = vec![1, 2, 3, 4, 5];

        let (credential_blob, secret) = context
            .execute_without_session(|ctx| {
                ctx.make_credential(key_handle, cred.try_into().unwrap(), key_name)
            })
            .expect("Call to make_credential failed");

        context.set_sessions((Some(session_1), Some(session_2), None));

        let decrypted = context
            .activate_credential(key_handle, key_handle, credential_blob, secret)
            .expect("Call to active_credential failed");

        let expected =
            Digest::try_from(vec![1, 2, 3, 4, 5]).expect("Failed to create digest for expected");

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
            .load(key_handle_unseal, result.out_private, &result.out_public)
            .unwrap();
        let unsealed = context.unseal(loaded_key.into()).unwrap();
        let unsealed = unsealed.value();
        assert!(unsealed == testbytes);
    }
}
