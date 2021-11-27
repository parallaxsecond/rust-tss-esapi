// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_quote {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{
            algorithm::HashingAlgorithm, resource_handles::Hierarchy,
            structure_tags::AttestationType,
        },
        structures::{AttestInfo, Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme},
    };

    #[test]
    fn pcr_quote() {
        let mut context = create_ctx_with_session();
        // Quote PCR 0
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build();
        // No qualifying data
        let qualifying_data = vec![0xff; 16];

        let key_handle = context
            .create_primary(Hierarchy::Owner, &signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

        let (attest, _signature) = context
            .quote(
                key_handle,
                &Data::try_from(qualifying_data).unwrap(),
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
}
