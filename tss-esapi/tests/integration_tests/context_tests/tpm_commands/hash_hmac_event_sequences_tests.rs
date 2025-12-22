// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod test_hash_sequence {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Hierarchy},
        structures::{MaxBuffer, Ticket},
    };

    #[test]
    fn test_hash_sequence_with_sha_256() {
        let mut context = create_ctx_with_session();

        let data = "There is no spoon";
        let expected_hashed_data: [u8; 32] = [
            0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
            0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
            0x43, 0x18, 0x5d, 0xc1,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let expected_ticked_digest: [u8; 64] = [
            110, 4, 245, 128, 239, 106, 77, 143, 97, 110, 11, 226, 49, 185, 114, 65, 0, 103, 164,
            8, 34, 233, 61, 243, 168, 49, 46, 191, 222, 53, 22, 44, 11, 2, 117, 139, 227, 103, 37,
            145, 245, 240, 240, 132, 193, 246, 159, 239, 90, 227, 34, 129, 224, 207, 72, 30, 71,
            172, 149, 76, 141, 183, 241, 110,
        ];

        let handle = context
            .hash_sequence_start(HashingAlgorithm::Sha256, None)
            .unwrap();
        context
            .sequence_update(
                handle,
                MaxBuffer::try_from(data.as_bytes().to_vec()).unwrap(),
            )
            .unwrap();
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(&[]).unwrap(),
                expected_hierarchy,
            )
            .unwrap();
        let ticket = ticket.unwrap();

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_eq!(ticket.digest().len(), expected_ticked_digest.len());
        assert_eq!(ticket.digest(), &expected_ticked_digest[..]);
    }

    #[test]
    fn test_hash_sequence_long() {
        let mut context = create_ctx_with_session();

        let data = [0xEE; 2 * 1025];
        let expected_hashed_data: [u8; 32] = [
            85, 49, 213, 201, 29, 99, 203, 43, 17, 142, 166, 204, 103, 133, 234, 67, 160, 165, 94,
            246, 210, 34, 63, 150, 131, 32, 20, 120, 122, 125, 176, 31,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let expected_ticked_digest: [u8; 64] = [
            201, 235, 122, 211, 109, 158, 194, 176, 243, 206, 249, 169, 3, 214, 42, 143, 213, 32,
            206, 158, 24, 102, 45, 140, 93, 212, 157, 14, 91, 70, 80, 175, 231, 79, 12, 130, 15,
            137, 218, 95, 217, 55, 73, 211, 51, 196, 48, 109, 92, 110, 168, 164, 223, 235, 246,
            209, 214, 198, 102, 60, 205, 193, 101, 210,
        ];

        let handle = context
            .hash_sequence_start(HashingAlgorithm::Sha256, None)
            .unwrap();

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chunk = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(handle, MaxBuffer::from_bytes(chunk).unwrap())
                .unwrap();
        }
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(last_chunk).unwrap(),
                expected_hierarchy,
            )
            .unwrap();
        let ticket = ticket.unwrap();

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_eq!(ticket.digest().len(), expected_ticked_digest.len());
        assert_eq!(ticket.digest(), &expected_ticked_digest[..]);
    }
}

mod test_hmac_sequence {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            reserved_handles::Hierarchy,
        },
        structures::{
            KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters, Ticket,
        },
    };

    #[test]
    fn test_hmac_sequence() {
        let mut context = create_ctx_with_session();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .expect("Failed to build public structure for key.");

        let key = context
            .create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            .unwrap();

        let data = [0xEE; 5000];
        let expected_hashed_data: [u8; 32] = [
            67, 164, 146, 77, 159, 46, 117, 152, 141, 131, 99, 4, 158, 204, 190, 90, 80, 191, 89,
            222, 18, 39, 161, 111, 70, 169, 161, 64, 248, 146, 241, 76,
        ];

        let handle = context
            .hmac_sequence_start(key.key_handle.into(), HashingAlgorithm::Sha256, None)
            .unwrap();

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chunk = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(handle, MaxBuffer::from_bytes(chunk).unwrap())
                .unwrap();
        }
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(last_chunk).unwrap(),
                Hierarchy::Null,
            )
            .unwrap();
        let ticket = ticket.unwrap();

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), Hierarchy::Null);
        assert_eq!(ticket.digest().len(), 0);
    }
}
