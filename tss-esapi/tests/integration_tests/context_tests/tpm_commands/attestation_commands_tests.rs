// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_quote {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::StructureTag,
        handles::KeyHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
            reserved_handles::Hierarchy,
            session_handles::AuthSession,
            structure_tags::AttestationType,
        },
        structures::{
            AttestInfo, Data, HashScheme, MaxBuffer, PcrSelectionListBuilder, PcrSlot,
            SignatureScheme, Ticket,
        },
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
                assert!(
                    !info.pcr_digest().is_empty(),
                    "Digest in QuoteInfo is empty"
                );
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

    #[test]
    fn time() {
        let mut context = create_ctx_with_session();
        // No qualifying data
        let qualifying_data = vec![0xff; 16];

        let key_handle = context
            .create_primary(Hierarchy::Owner, signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;
        let (attest, _signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.get_time(
                        key_handle,
                        Data::try_from(qualifying_data).unwrap(),
                        SignatureScheme::Null,
                    )
                },
            )
            .expect("Failed to get time");

        assert_eq!(
            AttestationType::Time,
            attest.attestation_type(),
            "Attestation type of the returned value is not indicating Time"
        );

        match attest.attested() {
            AttestInfo::Time { info: _ } => {}
            _ => {
                panic!("Attested did not contain the expected variant.")
            }
        }
    }

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

mod test_get_session_audit_digest {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::SessionType,
        handles::{ObjectHandle, SessionHandle},
        interface_types::{
            algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            reserved_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{Data, RsaExponent, RsaScheme, SignatureScheme, SymmetricDefinition},
        utils::create_unrestricted_signing_rsa_public,
    };

    #[test]
    fn test_get_session_audit_digest() {
        let mut context = create_ctx_without_session();
        let signing_key_pub = create_unrestricted_signing_rsa_public(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create signing rsa public structure");
        let sign_key_handle = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, signing_key_pub, None, None, None, None)
            })
            .unwrap()
            .key_handle;

        // Create an audit session with the audit attribute set
        let audit_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Failed to create audit session")
            .expect("Received invalid handle");

        let (session_attributes, session_attributes_mask) =
            SessionAttributesBuilder::new().with_audit(true).build();
        context
            .tr_sess_set_attributes(audit_session, session_attributes, session_attributes_mask)
            .expect("Failed to set audit attribute on session");

        // Use the audit session in a command so it has an audit digest
        context.set_sessions((Some(audit_session), None, None));
        let _ = context.read_public(sign_key_handle).unwrap();

        // Now get the session audit digest
        let session_handle = SessionHandle::from(audit_session);
        let (_attest, _signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.get_session_audit_digest(
                        ObjectHandle::Endorsement,
                        sign_key_handle,
                        session_handle,
                        Data::try_from(vec![0xff; 16]).unwrap(),
                        SignatureScheme::Null,
                    )
                },
            )
            .expect("Failed to get session audit digest");
    }
}

mod test_certify_x509 {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        handles::ObjectHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            reserved_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{
            Data, MaxBuffer, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaExponent,
            RsaScheme, SignatureScheme,
        },
    };

    /// DER-encoded partial X.509 certificate accepted by `TPM2_CertifyX509`.
    ///
    /// Structure (`SEQUENCE`):
    ///   * `issuer`  : `CN=rust-tss-esapi test`
    ///   * `validity`: 2020-01-01 .. 2040-01-01 (UTCTime)
    ///   * `subject` : `CN=rust-tss-esapi test`
    ///   * `subjectPublicKeyInfo` : placeholder (`rsaEncryption` OID + empty
    ///     `BIT STRING`). The TPM replaces this with the public key of the
    ///     object being certified.
    ///   * `[3] EXPLICIT extensions` : `keyUsage = digitalSignature | keyCertSign`
    ///     (critical).
    ///
    /// Bytes were produced from the `x509-cert` + `der` builder code; see this
    /// file's git history for the generator snippet.
    const PARTIAL_CERTIFICATE: &[u8] = &[
        0x30, 0x81, 0x86, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x13, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x74, 0x73, 0x73, 0x2d, 0x65, 0x73, 0x61, 0x70, 0x69,
        0x20, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34, 0x30, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x13, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x74, 0x73, 0x73, 0x2d, 0x65,
        0x73, 0x61, 0x70, 0x69, 0x20, 0x74, 0x65, 0x73, 0x74, 0x30, 0x10, 0x30, 0x0b, 0x06, 0x09,
        0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x03, 0x01, 0x00, 0xa3, 0x12, 0x30,
        0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
        0x02, 0x84,
    ];

    #[test]
    fn test_certify_x509() {
        let mut context = create_ctx_without_session();

        // Restricted RSASSA-SHA256 signing key with the `x509_sign` attribute
        // set, which is required for `TPM2_CertifyX509`.
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_restricted(true)
            .with_x509_sign(true)
            .build()
            .expect("Failed to build object attributes");

        let key_pub = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_scheme(
                        RsaScheme::create(
                            RsaSchemeAlgorithm::RsaSsa,
                            Some(HashingAlgorithm::Sha256),
                        )
                        .expect("Failed to create RSA scheme"),
                    )
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(true)
                    .with_is_decryption_key(false)
                    .with_restricted(true)
                    .build()
                    .expect("Failed to build RSA parameters"),
            )
            .with_rsa_unique_identifier(PublicKeyRsa::default())
            .build()
            .expect("Failed to build public");

        let key_handle = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
            })
            .expect("Failed to create primary signing key")
            .key_handle;

        let (added, tbs_digest, _signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.certify_x509(
                        ObjectHandle::from(key_handle),
                        key_handle,
                        Data::default(),
                        SignatureScheme::Null,
                        MaxBuffer::try_from(PARTIAL_CERTIFICATE.to_vec()).unwrap(),
                    )
                },
            )
            .expect("Failed to certify X.509");

        // The TPM must insert the version, serial number and SubjectPublicKeyInfo
        // (plus any spec-mandated extensions) — `addedToCertificate` is therefore
        // non-empty. `tbsDigest` is the SHA-256 (32-byte) digest of the full
        // TBSCertificate that was signed.
        assert!(!added.as_bytes().is_empty(), "addedToCertificate is empty");
        assert_eq!(tbs_digest.as_bytes().len(), 32);
    }
}

mod test_get_command_audit_digest {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{
            algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
            key_bits::RsaKeyBits,
            reserved_handles::Hierarchy,
            session_handles::AuthSession,
        },
        structures::{Data, RsaExponent, RsaScheme, SignatureScheme},
        utils::create_unrestricted_signing_rsa_public,
    };

    #[test]
    fn test_get_command_audit_digest() {
        let mut context = create_ctx_with_session();
        let signing_key_pub = create_unrestricted_signing_rsa_public(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create an unrestricted signing rsa public structure");
        let sign_key_handle = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(Hierarchy::Owner, signing_key_pub, None, None, None, None)
            })
            .unwrap()
            .key_handle;
        let (_attest, _signature) = context
            .execute_with_sessions(
                (
                    Some(AuthSession::Password),
                    Some(AuthSession::Password),
                    None,
                ),
                |ctx| {
                    ctx.get_command_audit_digest(
                        tss_esapi::handles::ObjectHandle::Endorsement,
                        sign_key_handle,
                        Data::try_from(vec![0xff; 16]).unwrap(),
                        SignatureScheme::Null,
                    )
                },
            )
            .expect("Failed to get command audit digest");
    }
}
