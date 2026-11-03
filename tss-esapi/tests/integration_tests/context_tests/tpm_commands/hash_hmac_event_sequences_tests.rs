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

        let handle = context
            .hash_sequence_start(HashingAlgorithm::Sha256, None)
            .expect("Hash sequence started successfully");
        context
            .sequence_update(
                handle,
                MaxBuffer::try_from(data.as_bytes().to_vec())
                    .expect("MaxBuffer created from raw data should succeed"),
            )
            .expect("Hash sequence update should succeed");
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(&[])
                    .expect("MaxBuffer created from empty buffer should succeed"),
                expected_hierarchy,
            )
            .expect("Hash sequence completed successfully");
        let ticket = ticket.expect("HashcheckTicket should be returned");

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_ne!(ticket.digest().len(), 0);
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

        let handle = context
            .hash_sequence_start(HashingAlgorithm::Sha256, None)
            .expect("Hash sequence started successfully");

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chunk = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(
                    handle,
                    MaxBuffer::from_bytes(chunk)
                        .expect("MaxBuffer created from raw data chunk should succeed"),
                )
                .expect("Hash sequence update should succeed");
        }
        let (actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(last_chunk)
                    .expect("MaxBuffer created from raw data last chunk should succeed"),
                expected_hierarchy,
            )
            .expect("Hash sequence completed successfully");
        let ticket = ticket.expect("HashcheckTicket should be returned");

        assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
        assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
        assert_eq!(ticket.hierarchy(), expected_hierarchy);
        assert_ne!(ticket.digest().len(), 0);
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
        structures::{KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters},
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
            .expect("Primary key created successfully");

        let data = [0xEE; 5000];

        let handle = context
            .hmac_sequence_start(key.key_handle.into(), HashingAlgorithm::Sha256, None)
            .expect("HMAC sequence started successfully");

        let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
        let last_chunk = chunks.remainder();
        for chunk in chunks {
            context
                .sequence_update(
                    handle,
                    MaxBuffer::from_bytes(chunk)
                        .expect("MaxBuffer created from raw data chunk should succeed"),
                )
                .expect("HMAC sequence update should succeed");
        }
        let (_actual_hashed_data, ticket) = context
            .sequence_complete(
                handle,
                MaxBuffer::from_bytes(last_chunk)
                    .expect("MaxBuffer created from raw data last chunk should succeed"),
                Hierarchy::Null,
            )
            .expect("HMAC sequence completed successfully");
        let _ticket = ticket.expect("HashcheckTicket should be returned");
    }
}

mod test_mac_sequence {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, MacSchemeAlgorithm, PublicAlgorithm},
            reserved_handles::Hierarchy,
        },
        structures::{KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters},
    };

    #[test]
    fn test_mac_sequence_matches_hmac_sequence() {
        let mut context = create_ctx_with_session();
        let object_attributes = ObjectAttributesBuilder::new()
            .with_sign_encrypt(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .build()
            .expect("Failed to build object attributes");
        let key_public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
                KeyedHashScheme::HMAC_SHA_256,
            ))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .expect("Failed to build public structure for key");
        let key_handle = context
            .create_primary(Hierarchy::Owner, key_public, None, None, None, None)
            .expect("Failed to create primary MAC key")
            .key_handle;
        let data = MaxBuffer::from_bytes(b"data authenticated by both sequence commands")
            .expect("Failed to create MAC input buffer");

        let mac_sequence = context
            .mac_sequence_start(key_handle.into(), MacSchemeAlgorithm::Sha256, None)
            .expect("Failed to start MAC sequence");
        context
            .sequence_update(mac_sequence, data.clone())
            .expect("Failed to update MAC sequence");
        let (mac_result, _) = context
            .sequence_complete(mac_sequence, MaxBuffer::default(), Hierarchy::Null)
            .expect("Failed to complete MAC sequence");

        let hmac_sequence = context
            .hmac_sequence_start(key_handle.into(), HashingAlgorithm::Sha256, None)
            .expect("Failed to start HMAC sequence");
        context
            .sequence_update(hmac_sequence, data)
            .expect("Failed to update HMAC sequence");
        let (hmac_result, _) = context
            .sequence_complete(hmac_sequence, MaxBuffer::default(), Hierarchy::Null)
            .expect("Failed to complete HMAC sequence");

        assert_eq!(hmac_result, mac_result);
        context
            .flush_context(key_handle.into())
            .expect("Failed to flush MAC key");
    }
}

mod test_event_sequence_complete {
    use crate::common::create_ctx_with_session;
    use sha2::{Digest as _, Sha256};
    use tss_esapi::{
        handles::PcrHandle,
        interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
        structures::MaxBuffer,
    };

    #[test]
    fn test_event_sequence_complete() {
        let mut context = create_ctx_with_session();
        let pcr_session = context.sessions().0;
        context
            .execute_with_session(pcr_session, |ctx| ctx.pcr_reset(PcrHandle::Pcr16))
            .expect("Failed to reset PCR 16 before test");

        let first_data = [0x01, 0x02, 0x03, 0x04];
        let final_data = [0x05, 0x06];
        let sequence_handle = context
            .hash_sequence_start(HashingAlgorithm::Null, None)
            .expect("Failed to start Event Sequence");
        context
            .sequence_update(
                sequence_handle,
                MaxBuffer::from_bytes(&first_data).expect("Failed to create first event buffer"),
            )
            .expect("Failed to update Event Sequence");
        let digest_values = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.event_sequence_complete(
                        PcrHandle::Pcr16,
                        sequence_handle,
                        MaxBuffer::from_bytes(&final_data)
                            .expect("Failed to create final event buffer"),
                    )
                },
            )
            .expect("Failed to complete Event Sequence");

        let expected_digest =
            Sha256::digest([first_data.as_slice(), final_data.as_slice()].concat());
        let actual_digest = digest_values
            .value()
            .get(&HashingAlgorithm::Sha256)
            .expect("Event Sequence did not return a SHA-256 digest");
        assert_eq!(&expected_digest[..], actual_digest.as_bytes());

        context
            .execute_with_session(pcr_session, |ctx| ctx.pcr_reset(PcrHandle::Pcr16))
            .expect("Failed to reset PCR 16 after test");
    }
}
