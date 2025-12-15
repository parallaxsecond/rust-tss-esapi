// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod test_hash_sequence {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Hierarchy},
        structures::{MaxBuffer, Ticket},
    };

    #[test]
    fn test_hash_sequence_with_sha_256() {
        let mut context = create_ctx_without_session();

        let data = "There is no spoon";
        let expected_hashed_data: [u8; 32] = [
            0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
            0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
            0x43, 0x18, 0x5d, 0xc1,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let expected_ticked_digest: [u8; 48] = [
            165, 70, 22, 78, 34, 29, 93, 104, 157, 3, 194, 141, 227, 62, 13, 113, 162, 117, 215,
            39, 206, 120, 56, 72, 177, 187, 242, 200, 129, 64, 216, 112, 77, 78, 135, 192, 40, 171,
            168, 40, 57, 132, 12, 101, 84, 148, 55, 125,
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
        assert_eq!(&ticket.digest()[..], &expected_ticked_digest[..]);
    }

    #[test]
    fn test_hash_sequence_long() {
        let mut context = create_ctx_without_session();

        let data = [0xEE; 5000];
        let expected_hashed_data: [u8; 32] = [
            32, 190, 228, 96, 206, 94, 17, 15, 13, 7, 50, 27, 254, 139, 228, 145, 230, 210, 2, 119,
            69, 16, 252, 245, 236, 126, 214, 6, 171, 196, 33, 212,
        ];
        let expected_hierarchy = Hierarchy::Owner;
        let expected_ticked_digest: [u8; 48] = [
            68, 142, 177, 202, 238, 232, 144, 173, 86, 148, 226, 71, 166, 84, 27, 61, 119, 133,
            122, 230, 74, 81, 149, 43, 193, 102, 99, 147, 2, 173, 120, 64, 69, 76, 62, 12, 231, 6,
            98, 78, 169, 120, 132, 199, 37, 190, 157, 156,
        ];

        let handle = context
            .hash_sequence_start(HashingAlgorithm::Sha256, None)
            .unwrap();

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chung = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(handle, MaxBuffer::from_bytes(&chunk).unwrap())
                .unwrap();
        }
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(&last_chung).unwrap(),
                expected_hierarchy,
            )
            .unwrap();
        let ticket = ticket.unwrap();

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_eq!(ticket.digest().len(), expected_ticked_digest.len());
        assert_eq!(&ticket.digest()[..], &expected_ticked_digest[..]);
    }
}

mod test_hmac_sequence {
    use crate::common::create_ctx_without_session;
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
    fn test_hmac() {
        let mut context = create_ctx_without_session();

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
            164, 220, 137, 242, 158, 130, 178, 240, 189, 138, 102, 104, 4, 75, 1, 100, 220, 199,
            160, 230, 120, 187, 239, 105, 51, 26, 185, 205, 83, 208, 254, 252,
        ];

        let handle = context
            .hmac_sequence_start(key.key_handle.into(), HashingAlgorithm::Sha256, None)
            .unwrap();

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chunk = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(handle, MaxBuffer::from_bytes(&chunk).unwrap())
                .unwrap();
        }
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(&last_chunk).unwrap(),
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
