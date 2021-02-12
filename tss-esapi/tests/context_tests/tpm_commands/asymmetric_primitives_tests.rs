// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_rsa_encrypt_decrypt {
    use crate::common::{create_ctx_with_session, encryption_decryption_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Auth, Data, PublicKeyRSA},
        utils::AsymSchemeUnion,
    };

    #[test]
    fn test_encrypt_decrypt() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &encryption_decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let scheme = AsymSchemeUnion::RSAOAEP(HashingAlgorithm::Sha256);

        let plaintext_bytes: Vec<u8> = vec![0x01, 0x02, 0x03];

        let plaintext = PublicKeyRSA::try_from(plaintext_bytes.clone()).unwrap();

        let ciphertext = context
            .rsa_encrypt(key_handle, plaintext, scheme, Data::default())
            .unwrap();

        assert_ne!(plaintext_bytes, ciphertext.value());

        let decrypted = context
            .rsa_decrypt(key_handle, ciphertext, scheme, Data::default())
            .unwrap();

        assert_eq!(plaintext_bytes, decrypted.value());
    }
}
