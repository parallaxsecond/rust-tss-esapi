// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_quote {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::tss::TPM2_ALG_NULL,
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Data, PcrSelectionListBuilder, PcrSlot},
        tss2_esys::TPMT_SIG_SCHEME,
    };

    #[test]
    fn pcr_quote() {
        let mut context = create_ctx_with_session();
        // Quote PCR 0
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build();
        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        // No qualifying data
        let qualifying_data = vec![0xff; 16];

        let key_handle = context
            .create_primary(Hierarchy::Owner, &signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

        let res = context
            .quote(
                key_handle,
                &Data::try_from(qualifying_data).unwrap(),
                scheme,
                pcr_selection_list,
            )
            .expect("Failed to get a quote");
        assert!(res.0.size != 0);
    }
}

mod test_certify {
    use crate::common::{create_ctx_with_session, decryption_key_pub, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::SessionType,
        interface_types::algorithm::HashingAlgorithm,
        interface_types::resource_handles::Hierarchy,
        structures::{
            Attest, AttestBuffer, AttestInfo, Auth, Data, SignatureScheme, SymmetricDefinition,
        },
    };

    #[test]
    fn test_certify() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let primary_key_handle = context
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

        // Generate the attesting key
        let result = context
            .create(
                primary_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap();
        let attesting_key = context
            .load(primary_key_handle, result.out_private, result.out_public)
            .unwrap();
        context
            .tr_set_auth(attesting_key.into(), &key_auth)
            .unwrap();

        // Generate the key to be attested
        let result = context
            .create(
                primary_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap();
        let attested_key = context
            .load(primary_key_handle, result.out_private, result.out_public)
            .unwrap();
        context.tr_set_auth(attested_key.into(), &key_auth).unwrap();
        // Get attested key name and qualified name
        let (_, attested_key_name, attested_key_qualified_name) =
            context.read_public(attested_key).unwrap();

        // Create sessions for authenticating the two objects
        let obj_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("obj_session: Failed to call start_auth_session")
            .expect("obj_session: Failed invalid session value");
        let sign_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("sign_session: Failed to call start_auth_session")
            .expect("sign_session: Failed invalid session value");

        let qualifying_data = Data::try_from(vec![1, 2, 3, 4, 5]).unwrap();
        context.execute_with_sessions((Some(obj_session), Some(sign_session), None), |ctx| {
            let (attest_buf, _sign) = ctx
                .certify(
                    attested_key.into(),
                    attesting_key,
                    qualifying_data,
                    SignatureScheme::NULL,
                )
                .unwrap();
            assert!(!attest_buf.value().is_empty());
            let attest = Attest::try_from(attest_buf)
                .expect("Failed to convert TPM2B_ATTEST to TPMS_ATTEST");
            match attest.attested() {
                AttestInfo::Certify {
                    name,
                    qualified_name,
                } => {
                    assert_eq!(name.value(), attested_key_name.value());
                    assert_eq!(qualified_name.value(), attested_key_qualified_name.value());
                }
                _ => panic!("Got wrong type of attestation info"),
            }
        });
    }

    #[test]
    fn attest_buffer_unmarshal_test() {
        let buffer_content = vec![0xff; 16];
        let attest =
            AttestBuffer::try_from(buffer_content).expect("Failed to create Attest buffer");
        assert!(Attest::try_from(attest).is_err());
    }
}
