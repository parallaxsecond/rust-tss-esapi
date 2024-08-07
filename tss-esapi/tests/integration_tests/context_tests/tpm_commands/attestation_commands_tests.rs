// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_quote {
    use crate::common::{create_ctx_with_session, signing_key_pub};

    #[cfg(feature = "abstraction")]
    use crate::common::decryption_key_pub;

    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{
            algorithm::HashingAlgorithm, reserved_handles::Hierarchy,
            structure_tags::AttestationType,
        },
        structures::{AttestInfo, Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme},
    };

    #[cfg(feature = "abstraction")]
    use tss_esapi::{
        constants::StructureTag,
        handles::KeyHandle,
        interface_types::{algorithm::SignatureSchemeAlgorithm, session_handles::AuthSession},
        structures::{HashScheme, MaxBuffer, Ticket},
        traits::Marshall,
    };

    #[test]
    fn pcr_quote() {
        let mut context = create_ctx_with_session();
        // Quote PCR 0
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build()
            .expect("Failed to create PcrSelectionList");
        // No qualifying data
        let qualifying_data = vec![0xff; 16];

        let key_handle = context
            .create_primary(Hierarchy::Owner, signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

        let (attest, _signature) = context
            .quote(
                key_handle,
                Data::try_from(qualifying_data).unwrap(),
                SignatureScheme::Null,
                pcr_selection_list.clone(),
            )
            .expect("Failed to get a quote");

        assert_eq!(
            AttestationType::Quote,
            attest.attestation_type(),
            "Attestation type of the returned value is not indicating Quote"
        );

        match attest.attested() {
            AttestInfo::Quote { info } => {
                assert!(info.pcr_digest().len() != 0, "Digest in QuoteInfo is empty");
                assert_eq!(
                    &pcr_selection_list,
                    info.pcr_selection(),
                    "QuoteInfo selection list did not match the input selection list"
                );
            }
            _ => {
                panic!("Attested did not contain the expected variant.")
            }
        }
    }

    #[cfg(feature = "abstraction")]
    #[test]
    fn certify() {
        let mut context = create_ctx_with_session();
        let qualifying_data = vec![0xff; 16];

        let sign_key_handle = context
            .create_primary(Hierarchy::Owner, signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;
        let obj_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (attest, signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.certify(
                        obj_key_handle.into(),
                        sign_key_handle,
                        Data::try_from(qualifying_data.clone()).unwrap(),
                        SignatureScheme::Null,
                    )
                },
            )
            .expect("Failed to certify object handle");

        // Verify the signature is valid for the attestation data

        let data = MaxBuffer::try_from(attest.marshall().unwrap())
            .expect("Failed to get data buffer from attestation data");
        let (digest, _) = context
            .hash(data, HashingAlgorithm::Sha256, Hierarchy::Null)
            .expect("Failed to hash data");

        let ticket = context
            .execute_with_nullauth_session(|ctx| {
                ctx.verify_signature(sign_key_handle, digest, signature)
            })
            .expect("Failed to verify signature");
        assert_eq!(ticket.tag(), StructureTag::Verified);

        // Verify the attestation data is as expected

        assert_eq!(attest.attestation_type(), AttestationType::Certify);
        assert!(matches!(attest.attested(), AttestInfo::Certify { .. }));
        assert_eq!(attest.extra_data().as_bytes(), qualifying_data);
    }

    #[cfg(feature = "abstraction")]
    #[test]
    fn certify_null() {
        let mut context = create_ctx_with_session();
        let qualifying_data = vec![0xff; 16];
        let sign_scheme = SignatureScheme::RsaPss {
            scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };

        let obj_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let (_attest, signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.certify(
                        obj_key_handle.into(),
                        KeyHandle::Null,
                        Data::try_from(qualifying_data).unwrap(),
                        sign_scheme,
                    )
                },
            )
            .expect("Failed to certify object handle");

        assert_eq!(signature.algorithm(), SignatureSchemeAlgorithm::Null);
    }

    #[cfg(feature = "abstraction")]
    #[test]
    fn certify_creation() {
        let mut context = create_ctx_with_session();
        let qualifying_data = vec![0xff; 16];

        let sign_key_handle = context
            .create_primary(Hierarchy::Owner, signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

        let create_result = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

        use std::convert::TryInto;

        let (attest, signature) = context
            .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
                ctx.certify_creation(
                    sign_key_handle,
                    create_result.key_handle.into(),
                    qualifying_data.try_into()?,
                    create_result.creation_hash,
                    SignatureScheme::Null,
                    create_result.creation_ticket,
                )
            })
            .expect("Failed to certify object handle creation");

        let data = MaxBuffer::try_from(attest.marshall().unwrap())
            .expect("Failed to get data buffer from attestation data");
        let (digest, _) = context
            .hash(data, HashingAlgorithm::Sha256, Hierarchy::Null)
            .expect("Failed to hash data");

        let ticket = context
            .execute_with_nullauth_session(|ctx| {
                ctx.verify_signature(sign_key_handle, digest, signature)
            })
            .expect("Failed to verify signature");
        assert_eq!(ticket.tag(), StructureTag::Verified);

        // Verify the attestation data is as expected
        assert_eq!(attest.attestation_type(), AttestationType::Creation);
        assert!(matches!(attest.attested(), AttestInfo::Creation { .. }));
    }
}
