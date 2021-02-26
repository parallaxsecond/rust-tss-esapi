// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{MaxBuffer, Ticket},
    };

    #[test]
    fn test_hash_with_sha_256() {
        let mut context = create_ctx_without_session();
        let data = "There is no spoon";
        let expected_hashed_data: [u8; 32] = [
            0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
            0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
            0x43, 0x18, 0x5d, 0xc1,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let (actual_hashed_data, ticket) = context
            .hash(
                &MaxBuffer::try_from(data.as_bytes().to_vec()).unwrap(),
                HashingAlgorithm::Sha256,
                expected_hierarchy,
            )
            .unwrap();
        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_ne!(ticket.digest().len(), 0); // Should do some better checking of the digest
    }
}

mod test_hmac {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        constants::tss::{TPM2_ALG_KEYEDHASH, TPM2_ALG_SHA256},
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{KeyedHashParameters, KeyedHashScheme, MaxBuffer},
        utils::{PublicParmsUnion, Tpm2BPublicBuilder},
    };

    #[test]
    fn test_hmac() {
        let mut context = create_ctx_with_session();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_KEYEDHASH)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_parms(PublicParmsUnion::KeyedHashDetail(KeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            )))
            .with_object_attributes(object_attributes)
            .build()
            .unwrap();

        let key = context
            .create_primary(Hierarchy::Owner, &key_pub, None, None, None, None)
            .unwrap();

        let data = vec![1, 2, 3, 4];

        let buf = MaxBuffer::try_from(data).unwrap();
        context
            .hmac(key.key_handle.into(), &buf, HashingAlgorithm::Sha256)
            .unwrap();
    }
}
