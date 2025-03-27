// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod test_quote {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        abstraction::{ak, ek, AsymmetricAlgorithmSelection},
        handles::PcrHandle,
        interface_types::{
            algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
            ecc::EccCurve,
            key_bits::RsaKeyBits,
        },
        structures::{
            Auth, Data, Digest, DigestList, DigestValues, EccSignature, PcrSelectionListBuilder,
            PcrSlot, Signature, SignatureScheme,
        },
        utils,
    };

    fn checkquote_ecc(hash_alg: HashingAlgorithm) {
        let mut context = create_ctx_with_session();
        let ek_ecc = ek::create_ek_object(
            &mut context,
            AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
            None,
        )
        .unwrap();
        // change pcr values for tests
        let mut vals = DigestValues::new();
        vals.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ])
            .unwrap(),
        );
        context.pcr_extend(PcrHandle::Pcr7, vals).unwrap();

        let ak_res = ak::create_ak(
            &mut context,
            ek_ecc,
            hash_alg,
            AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
            SignatureSchemeAlgorithm::EcDsa,
            None,
            None,
        )
        .unwrap();
        let ak_ecc = ak::load_ak(
            &mut context,
            ek_ecc,
            None,
            ak_res.out_private,
            ak_res.out_public.clone(),
        )
        .unwrap();

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot4])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot2])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .with_selection(HashingAlgorithm::Sha512, &[PcrSlot::Slot4])
            .build()
            .expect("Failed to create PcrSelectionList");
        let qualifying_data = vec![5, 2, 3, 8, 1, 4, 8, 28, 1, 4, 8, 2];
        let (attest, signature) = context
            .quote(
                ak_ecc,
                Data::try_from(qualifying_data.clone()).unwrap(),
                SignatureScheme::Null,
                pcr_selection_list.clone(),
            )
            .expect("Failed to get a quote");
        let (_update_counter, pcr_sel, pcr_data) = context
            .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))
            .unwrap();

        let public = ak_res.out_public;
        assert!(utils::checkquote(
            &attest,
            &signature,
            &public,
            &Some((pcr_sel.clone(), pcr_data.clone())),
            &qualifying_data
        )
        .unwrap());
        // Test without pcrs
        assert!(utils::checkquote(&attest, &signature, &public, &None, &qualifying_data).unwrap());

        let wrong_nonce = vec![5, 2, 3, 8, 1, 4, 8];
        assert!(!utils::checkquote(&attest, &signature, &public, &None, &wrong_nonce).unwrap());

        let wrong_ak_res = ak::create_ak(
            &mut context,
            ek_ecc,
            hash_alg,
            AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
            SignatureSchemeAlgorithm::EcDsa,
            None,
            None,
        )
        .unwrap();
        assert!(!utils::checkquote(
            &attest,
            &signature,
            &wrong_ak_res.out_public,
            &Some((pcr_sel.clone(), pcr_data.clone())),
            &qualifying_data
        )
        .unwrap());

        let wrong_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot4])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot2])
            .build()
            .expect("Failed to create PcrSelectionList");
        assert!(!utils::checkquote(
            &attest,
            &signature,
            &public,
            &Some((wrong_selection, pcr_data.clone())),
            &qualifying_data
        )
        .unwrap());

        let mut wrong_pcr_data = DigestList::new();
        for i in 1..pcr_data.len() {
            wrong_pcr_data.add(pcr_data.value()[i].clone()).unwrap();
        }
        wrong_pcr_data.add(pcr_data.value()[0].clone()).unwrap();
        assert!(!utils::checkquote(
            &attest,
            &signature,
            &public,
            &Some((pcr_sel.clone(), wrong_pcr_data)),
            &qualifying_data
        )
        .unwrap());

        let ecc = match signature {
            Signature::EcDsa(e) => e,
            _ => {
                panic!("Wrong signature created");
            }
        };
        let wrong_signature = EccSignature::create(
            HashingAlgorithm::Sha256,
            ecc.signature_s().clone(),
            ecc.signature_r().clone(),
        )
        .unwrap();
        assert!(!utils::checkquote(
            &attest,
            &Signature::EcDsa(wrong_signature),
            &public,
            &Some((pcr_sel.clone(), pcr_data.clone())),
            &qualifying_data
        )
        .unwrap());
    }

    #[test]
    fn checkquote_ecc_sha1() {
        checkquote_ecc(HashingAlgorithm::Sha1);
    }

    #[test]
    fn checkquote_ecc_sha256() {
        checkquote_ecc(HashingAlgorithm::Sha256);
    }

    fn checkquote_rsa(keybits: RsaKeyBits, hash_alg: HashingAlgorithm) {
        let mut context = create_ctx_with_session();
        let ek_rsa = ek::create_ek_object(
            &mut context,
            AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
            None,
        )
        .unwrap();
        let ak_auth = Auth::try_from(vec![0x1, 0x2, 0x42]).unwrap();
        let ak_rsa = ak::create_ak(
            &mut context,
            ek_rsa,
            hash_alg,
            AsymmetricAlgorithmSelection::Rsa(keybits),
            SignatureSchemeAlgorithm::RsaPss,
            Some(ak_auth.clone()),
            None,
        )
        .unwrap();
        let loaded_ak = ak::load_ak(
            &mut context,
            ek_rsa,
            Some(ak_auth),
            ak_rsa.out_private,
            ak_rsa.out_public.clone(),
        )
        .unwrap();

        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot7])
            .build()
            .expect("Failed to create PcrSelectionList");
        let qualifying_data = vec![5, 8, 1, 4, 8, 28, 18, 4, 8, 2];
        let (attest, signature) = context
            .quote(
                loaded_ak,
                Data::try_from(qualifying_data.clone()).unwrap(),
                SignatureScheme::Null,
                pcr_selection_list.clone(),
            )
            .expect("Failed to get a quote");
        let (_update_counter, pcr_sel, pcr_data) = context
            .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))
            .unwrap();

        assert!(utils::checkquote(
            &attest,
            &signature,
            &ak_rsa.out_public,
            &Some((pcr_sel.clone(), pcr_data.clone())),
            &qualifying_data
        )
        .unwrap());
    }

    #[test]
    fn checkquote_rsa_sha1() {
        checkquote_rsa(RsaKeyBits::Rsa2048, HashingAlgorithm::Sha1);
    }

    #[test]
    fn checkquote_rsa_sha256() {
        checkquote_rsa(RsaKeyBits::Rsa3072, HashingAlgorithm::Sha256);
    }
}
