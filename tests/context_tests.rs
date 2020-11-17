// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

const HASH: [u8; 64] = [
    0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0x69,
    0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84, 0xA2, 0x94,
    0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0xA2, 0x94, 0x8E,
    0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81, 0x37, 0x78, 0x37, 0x78,
];

const KEY: [u8; 512] = [
    231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71, 185, 1,
    209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140, 23, 139, 169, 15,
    193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248, 250, 100, 115, 214, 166,
    165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45, 8, 9, 36, 202, 171, 165, 43, 208,
    186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49, 214, 235, 151, 9, 189, 174,
    144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205, 54, 9, 181, 14, 35, 246, 49,
    150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18, 223, 179, 229, 0, 204, 65, 69, 166, 180,
    11, 49, 131, 96, 163, 96, 158, 7, 109, 119, 208, 17, 237, 125, 187, 121, 94, 65, 2, 86, 105,
    68, 51, 197, 73, 108, 185, 231, 126, 199, 81, 1, 251, 211, 45, 47, 15, 113, 135, 197, 152, 239,
    180, 111, 18, 192, 136, 222, 11, 99, 41, 248, 205, 253, 209, 56, 214, 32, 225, 3, 49, 161, 58,
    57, 190, 69, 86, 95, 185, 184, 155, 76, 8, 122, 104, 81, 222, 234, 246, 40, 98, 182, 90, 160,
    111, 74, 102, 36, 148, 99, 69, 207, 214, 104, 87, 128, 238, 26, 121, 107, 166, 4, 64, 5, 210,
    164, 162, 189, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

use std::convert::{TryFrom, TryInto};
use tss_esapi::{
    constants::{
        algorithm::{Cipher, HashingAlgorithm},
        tags::PropertyTag,
        tss::*,
        types::{capability::CapabilityType, session::SessionType},
    },
    handles::{
        AuthHandle, KeyHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, PcrHandle,
        PersistentTpmHandle, TpmHandle,
    },
    interface_types::{
        dynamic_handles::Persistent,
        resource_handles::{Hierarchy, NvAuth, Provision},
    },
    nv::storage::{NvIndexAttributes, NvPublicBuilder},
    session::Session,
    structures::{
        Auth, CapabilityData, Data, Digest, DigestList, DigestValues, MaxBuffer, MaxNvBuffer,
        Nonce, PcrSelectionListBuilder, PcrSlot, PublicKeyRSA, SensitiveData, Ticket,
    },
    tss2_esys::*,
    utils::{
        self, AsymSchemeUnion, ObjectAttributes, PublicIdUnion, PublicParmsUnion, Signature,
        SignatureData, Tpm2BPublicBuilder, TpmaSessionBuilder, TpmsRsaParmsBuilder,
    },
    Context,
};

mod common;
use common::{create_ctx_with_session, create_ctx_without_session};

fn create_public_sealed_object() -> tss_esapi::tss2_esys::TPM2B_PUBLIC {
    let mut object_attributes = utils::ObjectAttributes(0);
    object_attributes.set_fixed_tpm(true);
    object_attributes.set_fixed_parent(true);
    object_attributes.set_no_da(true);
    object_attributes.set_admin_with_policy(true);
    object_attributes.set_user_with_auth(true);

    let mut params: TPMU_PUBLIC_PARMS = Default::default();
    params.keyedHashDetail.scheme.scheme = tss_esapi::constants::tss::TPM2_ALG_NULL;

    tss_esapi::tss2_esys::TPM2B_PUBLIC {
        size: std::mem::size_of::<tss_esapi::tss2_esys::TPMT_PUBLIC>() as u16,
        publicArea: tss_esapi::tss2_esys::TPMT_PUBLIC {
            type_: tss_esapi::constants::tss::TPM2_ALG_KEYEDHASH,
            nameAlg: tss_esapi::constants::tss::TPM2_ALG_SHA256,
            objectAttributes: object_attributes.0,
            authPolicy: Default::default(),
            parameters: params,
            unique: Default::default(),
        },
    }
}

fn signing_key_pub() -> TPM2B_PUBLIC {
    utils::create_unrestricted_signing_rsa_public(
        AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
        2048,
        0,
    )
    .unwrap()
}

fn decryption_key_pub() -> TPM2B_PUBLIC {
    utils::create_restricted_decryption_rsa_public(Cipher::aes_256_cfb(), 2048, 0).unwrap()
}

fn encryption_decryption_key_pub() -> TPM2B_PUBLIC {
    utils::create_unrestricted_encryption_decryption_rsa_public(2048, 0).unwrap()
}

#[test]
fn comprehensive_test() {
    let mut context = create_ctx_with_session();
    let random_digest = context.get_random(16).unwrap();
    let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

    let creation_pcrs = PcrSelectionListBuilder::new().build();
    let prim_key_handle = context
        .create_primary_key(
            Hierarchy::Owner,
            &decryption_key_pub(),
            Some(&key_auth),
            None,
            None,
            creation_pcrs,
        )
        .unwrap()
        .0;

    let new_session = context
        .start_auth_session(
            None,
            Some(prim_key_handle.into()),
            None,
            SessionType::Hmac,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let session_attr = TpmaSessionBuilder::new()
        .with_flag(TPMA_SESSION_DECRYPT)
        .with_flag(TPMA_SESSION_ENCRYPT)
        .build();
    context
        .tr_sess_set_attributes(new_session.unwrap(), session_attr)
        .unwrap();
    context.set_sessions((new_session, None, None));

    let (key_priv, key_pub, _, _, _) = context
        .create_key(
            prim_key_handle,
            &signing_key_pub(),
            Some(&key_auth),
            None,
            None,
            PcrSelectionListBuilder::new().build(),
        )
        .unwrap();
    let key_handle = context.load(prim_key_handle, key_priv, key_pub).unwrap();

    let key_context = context.context_save(key_handle.into()).unwrap();
    let key_handle = context
        .context_load(key_context)
        .map(KeyHandle::from)
        .unwrap();
    context.tr_set_auth(key_handle.into(), &key_auth).unwrap();
    let scheme = TPMT_SIG_SCHEME {
        scheme: TPM2_ALG_NULL,
        details: Default::default(),
    };
    let validation = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    };
    let signature = context
        .sign(
            key_handle,
            &Digest::try_from(HASH[..32].to_vec()).unwrap(),
            scheme,
            validation.try_into().unwrap(),
        )
        .unwrap();
    context
        .verify_signature(
            key_handle,
            &Digest::try_from(HASH[..32].to_vec()).unwrap(),
            signature,
        )
        .unwrap();
}

mod test_start_sess {
    use super::*;

    #[test]
    fn test_simple_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_nonce_sess() {
        let mut context = create_ctx_without_session();
        context
            .start_auth_session(
                None,
                None,
                Some(
                    Nonce::try_from(
                        [
                            128, 85, 22, 124, 85, 9, 12, 55, 23, 73, 1, 244, 102, 44, 95, 39, 10,
                        ]
                        .to_vec(),
                    )
                    .unwrap(),
                )
                .as_ref(),
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_bound_sess() {
        let mut context = create_ctx_with_session();
        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        context
            .start_auth_session(
                Some(prim_key_handle),
                Some(prim_key_handle.into()),
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_encrypted_start_sess() {
        let mut context = create_ctx_without_session();
        let encrypted_sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(encrypted_sess.unwrap(), session_attr)
            .unwrap();

        let _ = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();
    }

    #[test]
    fn test_authenticated_start_sess() {
        let mut context = create_ctx_without_session();
        let auth_sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap();

        context.execute_with_session(auth_sess, |ctx| {
            ctx.start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .unwrap_err();
        });
    }
}

mod test_get_capability {
    use super::*;

    #[test]
    fn test_get_capability() {
        let mut context = create_ctx_without_session();
        let (res, _more) = context
            .get_capabilities(CapabilityType::TPMProperties, TPM2_PT_VENDOR_STRING_1, 4)
            .unwrap();
        match res {
            CapabilityData::TPMProperties(props) => {
                assert_ne!(props.len(), 0);
            }
            _ => panic!("Invalid properties returned"),
        };
    }

    #[test]
    fn test_get_tpm_property() {
        let mut context = create_ctx_without_session();

        let rev = context
            .get_tpm_property(PropertyTag::Revision)
            .unwrap()
            .unwrap();
        assert_ne!(rev, 0);

        let year = context
            .get_tpm_property(PropertyTag::Year)
            .unwrap()
            .unwrap();
        assert_ne!(year, 0);
    }
}

mod test_pcr_extend_reset {
    use super::*;

    #[test]
    fn test_pcr_extend_reset_commands() {
        // In this test, we use PCR16. This was chosen because it's the only one that is
        // resettable and extendable from the locality in which we are running, and does not
        // get reset by any D-RTPM events.
        // PCR (TCG PC Client Platform TPM Profile (PTP) for TPM 2.0 Version 1.05 Rev 14)
        let mut context = create_ctx_with_session();
        let pcr_ses = context.sessions().0;

        // We start by resetting. We do not place any expectations on the prior contents
        context.execute_with_session(pcr_ses, |ctx| ctx.pcr_reset(PcrHandle::Pcr16).unwrap());

        // Read PCR contents
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot16])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build();
        // pcr_read is NO_SESSIONS
        let (_, _, pcr_data) =
            context.execute_without_session(|ctx| ctx.pcr_read(&pcr_selection_list).unwrap());
        let pcr_sha1_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha1).unwrap();
        let pcr_sha256_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha256).unwrap();
        let pcr_sha1_value = pcr_sha1_bank.pcr_value(PcrSlot::Slot16).unwrap();
        let pcr_sha256_value = pcr_sha256_bank.pcr_value(PcrSlot::Slot16).unwrap();
        // Needs to have the length of associated with the hashing algorithm
        assert_eq!(pcr_sha1_value.value(), [0; 20]);
        assert_eq!(pcr_sha256_value.value(), [0; 32]);

        // Extend both sha256 and sha1
        let mut vals = DigestValues::new();
        vals.set(
            HashingAlgorithm::Sha1,
            Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            ])
            .unwrap(),
        );
        vals.set(
            HashingAlgorithm::Sha256,
            Digest::try_from(vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ])
            .unwrap(),
        );
        // The extend and reset functions are all SESSIONS
        context.execute_with_session(pcr_ses, |ctx| {
            ctx.pcr_extend(PcrHandle::Pcr16, vals).unwrap()
        });

        // Read PCR contents
        let (_, _, pcr_data) =
            context.execute_without_session(|ctx| ctx.pcr_read(&pcr_selection_list).unwrap());
        let pcr_sha1_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha1).unwrap();
        let pcr_sha256_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha256).unwrap();
        let pcr_sha1_value = pcr_sha1_bank.pcr_value(PcrSlot::Slot16).unwrap();
        let pcr_sha256_value = pcr_sha256_bank.pcr_value(PcrSlot::Slot16).unwrap();
        // Needs to have the length of associated with the hashing algorithm
        /*
          Right Hand Side determined by:
          python3
          >>> from hashlib import sha1
          >>> m = sha1()
          >>> m.update(b"\0" * 20)
          >>> m.update(bytes(range(1,21)))
          >>> it = iter(m.hexdigest())
          >>> res = ["0x"+a+b for a,b in zip(it, it)]
          >>> ", ".join(res)
        */
        assert_eq!(
            pcr_sha1_value.value(),
            [
                0x5f, 0x42, 0x0e, 0x04, 0x95, 0x8b, 0x2e, 0x3f, 0x18, 0x07, 0x39, 0x1e, 0x99, 0xd9,
                0x49, 0x2c, 0x67, 0xaa, 0xef, 0xfd
            ]
        );
        assert_eq!(
            pcr_sha256_value.value(),
            [
                0x0b, 0x8f, 0x4c, 0x5b, 0x6a, 0xdc, 0x4c, 0x08, 0x7a, 0xb9, 0xf4, 0x3a, 0xae, 0xb6,
                0x00, 0x70, 0x84, 0xc2, 0x64, 0xad, 0xca, 0xa3, 0xcb, 0x07, 0x17, 0x6b, 0x79, 0x23,
                0x42, 0x85, 0x04, 0x12
            ]
        );

        // Now reset it again to test it's again zeroes
        context.execute_with_session(pcr_ses, |ctx| ctx.pcr_reset(PcrHandle::Pcr16).unwrap());

        // Read PCR contents
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot16])
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build();
        let (_, _, pcr_data) =
            context.execute_without_session(|ctx| ctx.pcr_read(&pcr_selection_list).unwrap());
        let pcr_sha1_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha1).unwrap();
        let pcr_sha256_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha256).unwrap();
        let pcr_sha1_value = pcr_sha1_bank.pcr_value(PcrSlot::Slot16).unwrap();
        let pcr_sha256_value = pcr_sha256_bank.pcr_value(PcrSlot::Slot16).unwrap();
        // Needs to have the length of associated with the hashing algorithm
        assert_eq!(pcr_sha1_value.value(), [0; 20]);
        assert_eq!(pcr_sha256_value.value(), [0; 32]);
    }
}

mod test_pcr_read {
    use super::*;

    #[test]
    fn test_pcr_read_command() {
        let mut context = create_ctx_without_session();
        // Read PCR 0
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build();
        let input: TPML_PCR_SELECTION = pcr_selection_list.clone().into();
        // Verify input
        assert_eq!(pcr_selection_list.len(), 1);
        assert_eq!(input.count as usize, pcr_selection_list.len());
        assert_eq!(input.pcrSelections[0].sizeofSelect, 3);
        assert_eq!(
            input.pcrSelections[0].hash,
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha256)
        );
        assert_eq!(input.pcrSelections[0].pcrSelect[0], 0b0000_0001);
        assert_eq!(input.pcrSelections[0].pcrSelect[1], 0b0000_0000);
        assert_eq!(input.pcrSelections[0].pcrSelect[2], 0b0000_0000);
        // Read the pcr slots.
        let (update_counter, pcr_selection_list_out, pcr_data) =
            context.pcr_read(&pcr_selection_list).unwrap();

        // Verify that the selected slots have been read.
        assert_ne!(update_counter, 0);
        let output: TPML_PCR_SELECTION = pcr_selection_list_out.into();
        assert_eq!(output.count, input.count);
        assert_eq!(
            output.pcrSelections[0].sizeofSelect,
            input.pcrSelections[0].sizeofSelect
        );
        assert_eq!(input.pcrSelections[0].hash, output.pcrSelections[0].hash);
        assert_eq!(
            input.pcrSelections[0].pcrSelect[0],
            output.pcrSelections[0].pcrSelect[0]
        );
        assert_eq!(
            input.pcrSelections[0].pcrSelect[1],
            output.pcrSelections[0].pcrSelect[1]
        );
        assert_eq!(
            input.pcrSelections[0].pcrSelect[2],
            output.pcrSelections[0].pcrSelect[2]
        );

        // Only the specified in the selection should be present.
        assert_eq!(pcr_data.len(), output.count as usize);
        let pcr_bank = pcr_data.pcr_bank(HashingAlgorithm::Sha256).unwrap();
        // Only one value selected
        assert_eq!(pcr_bank.len(), 1);
        let pcr_value = pcr_bank.pcr_value(PcrSlot::Slot0).unwrap();
        // Needs to have the length of associated with the hashing algorithm
        assert_eq!(pcr_value.value().len(), TPM2_SHA256_DIGEST_SIZE as usize);
    }

    #[test]
    fn test_pcr_read_large_pcr_selections() {
        // If the pcr Selection contains more then 16 values
        // then not all can be read at once and the returned
        // pcr selections will differ from the original.
        let mut context = create_ctx_without_session();
        let pcr_selection_list_in = PcrSelectionListBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[
                    PcrSlot::Slot0,
                    PcrSlot::Slot1,
                    PcrSlot::Slot2,
                    PcrSlot::Slot3,
                    PcrSlot::Slot4,
                    PcrSlot::Slot5,
                    PcrSlot::Slot6,
                    PcrSlot::Slot7,
                    PcrSlot::Slot8,
                    PcrSlot::Slot9,
                    PcrSlot::Slot10,
                    PcrSlot::Slot11,
                    PcrSlot::Slot12,
                    PcrSlot::Slot13,
                    PcrSlot::Slot14,
                    PcrSlot::Slot15,
                    PcrSlot::Slot16,
                ],
            )
            .build();
        let (_update_counter, pcr_selection_list_out, _pcr_data) =
            context.pcr_read(&pcr_selection_list_in).unwrap();
        assert_ne!(pcr_selection_list_in, pcr_selection_list_out);
    }
}

mod test_unseal {
    use super::*;

    #[test]
    fn unseal() {
        let testbytes: [u8; 5] = [0x01, 0x02, 0x03, 0x04, 0x42];

        let mut context = create_ctx_with_session();

        let key_handle_seal = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        let key_handle_unseal = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                None,
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let key_pub = create_public_sealed_object();
        let (sealed_priv, sealed_pub, _, _, _) = context
            .create_key(
                key_handle_seal,
                &key_pub,
                None,
                Some(SensitiveData::try_from(testbytes.to_vec()).unwrap()).as_ref(),
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();
        let loaded_key = context
            .load(key_handle_unseal, sealed_priv, sealed_pub)
            .unwrap();
        let unsealed = context.unseal(loaded_key.into()).unwrap();
        let unsealed = unsealed.value();
        assert!(unsealed == testbytes);
    }
}

mod test_quote {
    use super::*;

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
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                None,
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

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

fn get_pcr_policy_digest(context: &mut Context, mangle: bool, do_trial: bool) -> (Digest, Session) {
    let old_ses = context.sessions();
    context.clear_sessions();

    // Read the pcr values using pcr_read
    let pcr_selection_list = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
        .build();

    let (_update_counter, pcr_selection_list_out, pcr_data) =
        context.pcr_read(&pcr_selection_list).unwrap();

    assert_eq!(pcr_selection_list, pcr_selection_list_out);
    // Run pcr_policy command.
    //
    // "If this command is used for a trial policySession,
    // policySession→policyDigest will be updated using the
    // values from the command rather than the values from a digest of the TPM PCR."
    //
    // "TPM2_Quote() and TPM2_PolicyPCR() digest the concatenation of PCR."
    let mut concatenated_pcr_values = [
        pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .unwrap()
            .pcr_value(PcrSlot::Slot0)
            .unwrap()
            .value(),
        pcr_data
            .pcr_bank(HashingAlgorithm::Sha256)
            .unwrap()
            .pcr_value(PcrSlot::Slot1)
            .unwrap()
            .value(),
    ]
    .concat();

    if mangle {
        concatenated_pcr_values[0] = 0x00;
    }

    let (hashed_data, _ticket) = context
        .hash(
            &MaxBuffer::try_from(concatenated_pcr_values.to_vec()).unwrap(),
            HashingAlgorithm::Sha256,
            Hierarchy::Owner,
        )
        .unwrap();

    if do_trial {
        let pcr_ses = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let pcr_ses_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(pcr_ses, pcr_ses_attr)
            .unwrap();

        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(pcr_ses, &hashed_data, pcr_selection_list)
            .unwrap();

        // There is now a policy digest that can be retrived and used.
        let digest = context.policy_get_digest(pcr_ses).unwrap();

        // Restore old sessions
        context.set_sessions(old_ses);

        (digest, pcr_ses)
    } else {
        let pcr_ses = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let pcr_ses_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(pcr_ses, pcr_ses_attr)
            .unwrap();

        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(pcr_ses, &hashed_data, pcr_selection_list)
            .unwrap();

        // There is now a policy digest that can be retrived and used.
        let digest = context.policy_get_digest(pcr_ses).unwrap();

        // Restore old sessions
        context.set_sessions(old_ses);

        (digest, pcr_ses)
    }
}

mod test_policies {
    use super::*;

    #[test]
    fn test_policy_authorize() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        let key_name = context.tr_get_name(key_handle.into()).unwrap();

        let policy_ref: TPM2B_NONCE = Default::default();
        let (policy_digest, policy_ses) = get_pcr_policy_digest(&mut context, false, false);

        // aHash ≔ H_{aHashAlg}(approvedPolicy || policyRef)
        let ahash = context
            .hash(
                &MaxBuffer::try_from(policy_digest.value().to_vec()).unwrap(),
                HashingAlgorithm::Sha256,
                Hierarchy::Null,
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        // A signature over just the policy_digest, since the policy_ref is empty
        let signature = context
            .sign(key_handle, &ahash, scheme, validation.try_into().unwrap())
            .unwrap();
        let tkt = context
            .verify_signature(key_handle, &ahash, signature)
            .unwrap();

        // Since the signature is over this sessions' state, it should be valid
        context
            .policy_authorize(
                policy_ses,
                &policy_digest,
                &Nonce::try_from(policy_ref).unwrap(),
                &key_name,
                tkt,
            )
            .unwrap();
    }

    #[test]
    fn test_policy_or() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        let mut digest_list = DigestList::new();
        digest_list
            .add(get_pcr_policy_digest(&mut context, true, true).0)
            .unwrap();
        digest_list
            .add(get_pcr_policy_digest(&mut context, false, true).0)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_or(trial_session, digest_list).unwrap();
    }

    #[test]
    fn test_policy_locality() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_locality(trial_session, 3).unwrap();
    }

    #[test]
    fn test_policy_command_code() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_command_code(trial_session, TPM2_CC_Unseal)
            .unwrap();
    }

    #[test]
    fn test_policy_physical_presence() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_physical_presence(trial_session).unwrap();
    }

    #[test]
    fn test_policy_cp_hash() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_cp_hash(trial_session, &test_dig).unwrap();
    }
    #[test]
    fn test_policy_name_hash() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_name_hash(trial_session, &test_dig).unwrap();
    }
    #[test]
    fn test_policy_auth_value() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_auth_value(trial_session).unwrap();
    }
    #[test]
    fn test_policy_password() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_password(trial_session).unwrap();
    }
    #[test]
    fn test_policy_nv_written() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_nv_written(trial_session, true).unwrap();
    }
}

mod test_policy_pcr {
    use super::*;

    #[test]
    fn test_policy_pcr_sha_256() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // Read the pcr values using pcr_read
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
            .build();

        let (_update_counter, pcr_selection_list_out, pcr_data) =
            context.pcr_read(&pcr_selection_list).unwrap();

        assert_eq!(pcr_selection_list, pcr_selection_list_out);
        // Run pcr_policy command.
        //
        // "If this command is used for a trial policySession,
        // policySession→policyDigest will be updated using the
        // values from the command rather than the values from a digest of the TPM PCR."
        //
        // "TPM2_Quote() and TPM2_PolicyPCR() digest the concatenation of PCR."
        let concatenated_pcr_values = MaxBuffer::try_from(
            [
                pcr_data
                    .pcr_bank(HashingAlgorithm::Sha256)
                    .unwrap()
                    .pcr_value(PcrSlot::Slot0)
                    .unwrap()
                    .value(),
                pcr_data
                    .pcr_bank(HashingAlgorithm::Sha256)
                    .unwrap()
                    .pcr_value(PcrSlot::Slot1)
                    .unwrap()
                    .value(),
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

        let (hashed_data, _ticket) = context
            .hash(
                &concatenated_pcr_values,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
            .unwrap();
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(trial_session, &hashed_data, pcr_selection_list)
            .unwrap();
    }
}

mod test_get_random {
    use super::*;

    #[test]
    fn test_encrypted_get_rand() {
        let mut context = create_ctx_with_session();
        let encrypted_sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(encrypted_sess, session_attr)
            .unwrap();

        context.set_sessions((Some(encrypted_sess), None, None));
        let _ = context.get_random(10).unwrap();
    }

    #[test]
    fn test_authenticated_get_rand() {
        let mut context = create_ctx_with_session();
        let auth_sess = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        context.set_sessions((Some(auth_sess), None, None));
        let _ = context.get_random(10).unwrap_err();
    }

    #[test]
    fn test_get_0_rand() {
        let mut context = create_ctx_with_session();
        let _ = context.get_random(0);
    }
}

mod test_create_primary {
    use super::*;

    #[test]
    fn test_create_primary() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        assert!(ESYS_TR::from(key_handle) != ESYS_TR_NONE);
    }
}

mod test_create {
    use super::*;

    #[test]
    fn test_create() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let _ = context
            .create_key(
                prim_key_handle,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();
    }
}

mod test_load {
    use super::*;

    #[test]
    fn test_load() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let (private, public, _, _, _) = context
            .create_key(
                prim_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();

        let _ = context.load(prim_key_handle, private, public).unwrap();
    }
}

mod test_sign {
    use super::*;

    #[test]
    fn test_sign() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn test_sign_empty_digest() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                &Digest::try_from(Vec::<u8>::new()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap_err();
    }

    #[test]
    fn test_sign_large_digest() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        context
            .sign(
                key_handle,
                &Digest::try_from([0xbb; 40].to_vec()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap_err();
    }
}

mod test_rsa_encrypt_decrypt {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &encryption_decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

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

mod test_verify_sig {
    use super::*;

    #[test]
    fn test_verify_sig() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = context
            .sign(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap();

        context
            .verify_signature(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .unwrap();
    }

    #[test]
    fn test_verify_wrong_sig() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let mut signature = context
            .sign(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap();

        if let SignatureData::RsaSignature(signature) = &mut signature.signature {
            signature.reverse();
        }
        assert!(context
            .verify_signature(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    fn test_verify_wrong_sig_2() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            signature: SignatureData::RsaSignature(vec![0xab; 500]),
        };
        assert!(context
            .verify_signature(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    fn test_verify_wrong_sig_3() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            signature: SignatureData::RsaSignature(vec![0; 0]),
        };
        assert!(context
            .verify_signature(
                key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }
}

mod test_load_ext {
    use super::*;

    pub fn get_ext_rsa_pub() -> TPM2B_PUBLIC {
        let scheme = AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256);
        let rsa_parms = TpmsRsaParmsBuilder::new_unrestricted_signing_key(scheme, 2048, 0)
            .build()
            .unwrap(); // should not fail as we control the params
        let mut object_attributes = ObjectAttributes(0);
        object_attributes.set_user_with_auth(true);
        object_attributes.set_decrypt(false);
        object_attributes.set_sign_encrypt(true);
        object_attributes.set_restricted(false);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: 256,
            buffer: KEY,
        };
        let pub_key = PublicIdUnion::Rsa(Box::from(pub_buffer));

        Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(object_attributes)
            .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
            .with_unique(pub_key)
            .build()
            .unwrap() // should not fail as we control the params
    }

    #[test]
    fn test_load_ext_pub() {
        let mut context = create_ctx_with_session();
        let pub_key = get_ext_rsa_pub();

        context
            .load_external_public(&pub_key, Hierarchy::Owner)
            .unwrap();
    }
}

mod test_read_pub {
    use super::*;

    #[test]
    fn test_read_pub() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_flush_context {
    use super::*;

    #[test]
    fn test_flush_ctx() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        context.flush_context(key_handle.into()).unwrap();
        assert!(context.read_public(key_handle).is_err());
    }

    #[test]
    fn test_flush_parent_ctx() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let (private, public, _, _, _) = context
            .create_key(
                prim_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_ctx_save {
    use super::*;

    #[test]
    fn test_ctx_save() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;
        let _ = context.context_save(key_handle.into()).unwrap();
    }

    #[test]
    fn test_ctx_save_leaf() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let (private, public, _, _, _) = context
            .create_key(
                prim_key_handle,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let _ = context.context_save(key_handle.into()).unwrap();
    }
}

mod test_ctx_load {
    use super::*;

    #[test]
    fn test_ctx_load() {
        let mut context = create_ctx_with_session();
        let key_auth = context.get_random(16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(Auth::try_from(key_auth.value().to_vec()).unwrap()).as_ref(),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let (private, public, _, _, _) = context
            .create_key(
                prim_key_handle,
                &signing_key_pub(),
                Some(Auth::try_from(key_auth.value().to_vec()).unwrap()).as_ref(),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap();

        let key_handle = context.load(prim_key_handle, private, public).unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let key_ctx = context.context_save(key_handle.into()).unwrap();
        let key_handle = context.context_load(key_ctx).map(KeyHandle::from).unwrap();
        let _ = context.read_public(key_handle).unwrap();
    }
}

mod test_evict_control {
    use super::*;

    fn remove_persitent_handle(persistent_tpm_handle: PersistentTpmHandle) {
        let mut context = create_ctx_without_session();
        if let Ok(mut handle) =
            context.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
        {
            // The peristent handle existed and is now loaded
            // so it needs to be evicted
            context.execute_with_session(Some(Session::Password), |ctx| {
                ctx.evict_control(
                    Provision::Owner,
                    handle,
                    Persistent::Persistent(persistent_tpm_handle),
                )
                .expect("Failed to evict persitent handle");
            });
            // close the handle.
            context.execute_without_session(|ctx| {
                ctx.tr_close(&mut handle).expect("Failed to close handle");
            });
        }
    }

    #[test]
    fn test_basic_evict_control() {
        // Create persistent TPM handle with
        let persistent_tpm_handle =
            PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))
                .expect("Failed to create persitent tpm handle");
        // Create interface type Persistent by using the handle.
        let persistent = Persistent::Persistent(persistent_tpm_handle);

        // Make sure the handle is not already persistent
        remove_persitent_handle(persistent_tpm_handle);

        // Create context
        let mut context = create_ctx_without_session();

        // Set Password session
        context.set_sessions((Some(Session::Password), None, None));

        // Create primary key handle
        let auth_value_primary = Auth::try_from(vec![1, 2, 3, 4, 5])
            .expect("Failed to crate auth value for primary key");
        let primary_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &decryption_key_pub(),
                Some(auth_value_primary).as_ref(),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .expect("Failed to create primary key")
            .0;

        // Evict control to make primary_key_handle persistent
        let mut peristent_primary_key_handle = context
            .evict_control(Provision::Owner, primary_key_handle.into(), persistent)
            .expect("Failed to make the primary key handle persistent");

        // Flush out the primary_key_handle
        context
            .flush_context(ObjectHandle::from(primary_key_handle))
            .expect("Failed to flush context");
        // Close the persistant_handle returned by evict_control
        context
            .tr_close(&mut peristent_primary_key_handle)
            .expect("Failed to close persistant handle");

        // Retrieve the handle from the tpm again.
        let retireved_persistant_handle = context.execute_without_session(|ctx| {
            ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
                .expect("Failed to load the persistant handle")
        });

        // Evict the persitent handle from the tpm
        context
            .evict_control(Provision::Owner, retireved_persistant_handle, persistent)
            .expect("Failed to evict persistent handle");

        context.clear_sessions();

        assert_ne!(
            retireved_persistant_handle,
            ObjectHandle::from(ESYS_TR_NONE)
        );
    }
}

mod test_handle_auth {
    use super::*;

    #[test]
    fn test_set_handle_auth() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();
        let prim_key_handle = context
            .create_primary_key(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                PcrSelectionListBuilder::new().build(),
            )
            .unwrap()
            .0;

        let key_ctx = context.context_save(prim_key_handle.into()).unwrap();
        context.flush_context(prim_key_handle.into()).unwrap();
        let new_key_handle = context.context_load(key_ctx).map(KeyHandle::from).unwrap();

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };

        context
            .tr_set_auth(new_key_handle.into(), &key_auth)
            .unwrap();
        let _ = context
            .sign(
                new_key_handle,
                &Digest::try_from(HASH[..32].to_vec()).unwrap(),
                scheme,
                validation.try_into().unwrap(),
            )
            .unwrap();
    }

    // Test is ignored as the current version of the TSS library segfaults on the `set auth` call
    // with `ESYS_TR_NONE` as the handle.
    // See: https://github.com/tpm2-software/tpm2-tss/issues/1593
    #[ignore]
    #[test]
    fn test_invalid_handle() {
        let mut context = create_ctx_with_session();
        context
            .tr_set_auth(
                ESYS_TR_NONE.into(),
                &Auth::try_from([0x11; 10].to_vec()).unwrap(),
            )
            .unwrap_err();
    }
}

mod test_session_attr {
    use super::*;

    #[test]
    fn test_session_attr() {
        let mut context = create_ctx_with_session();
        let sess_handle = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let sess_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .with_flag(TPMA_SESSION_AUDIT)
            .build();
        context
            .tr_sess_set_attributes(sess_handle, sess_attr)
            .unwrap();
        context.set_sessions((Some(sess_handle), None, None));

        let _ = context.get_random(10).unwrap();
    }
}

mod test_test_parms {
    use super::*;

    #[test]
    fn test_sym_parms() {
        let mut context = create_ctx_without_session();
        let cipher = Cipher::aes_256_cfb();
        context
            .test_parms(PublicParmsUnion::SymDetail(cipher))
            .unwrap();
    }
}

mod test_hash {
    use super::*;

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

mod test_policy_get_digest {
    use super::*;
    #[test]
    fn get_policy_digest() {
        let mut context = create_ctx_without_session();
        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                Cipher::aes_256_cfb(),
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let trial_session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context
            .tr_sess_set_attributes(trial_session, trial_session_attr)
            .unwrap();

        // Read the pcr values using pcr_read
        let pcr_selection_list = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
            .build();

        let (_update_counter, pcr_selection_list_out, pcr_data) =
            context.pcr_read(&pcr_selection_list).unwrap();

        assert_eq!(pcr_selection_list, pcr_selection_list_out);
        // Run pcr_policy command.
        //
        // "If this command is used for a trial policySession,
        // policySession→policyDigest will be updated using the
        // values from the command rather than the values from a digest of the TPM PCR."
        //
        // "TPM2_Quote() and TPM2_PolicyPCR() digest the concatenation of PCR."
        let concatenated_pcr_values = MaxBuffer::try_from(
            [
                pcr_data
                    .pcr_bank(HashingAlgorithm::Sha256)
                    .unwrap()
                    .pcr_value(PcrSlot::Slot0)
                    .unwrap()
                    .value(),
                pcr_data
                    .pcr_bank(HashingAlgorithm::Sha256)
                    .unwrap()
                    .pcr_value(PcrSlot::Slot1)
                    .unwrap()
                    .value(),
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

        let (hashed_data, _ticket) = context
            .hash(
                &concatenated_pcr_values,
                HashingAlgorithm::Sha256,
                Hierarchy::Owner,
            )
            .unwrap();
        // There should be no errors setting pcr policy for trial session.
        context
            .policy_pcr(trial_session, &hashed_data, pcr_selection_list)
            .unwrap();

        // There is now a policy digest that can be retrived and used.
        let retrieved_policy_digest = context.policy_get_digest(trial_session).unwrap();

        // The algorithm is SHA256 so the expected size of the digest should be 32.
        assert_eq!(retrieved_policy_digest.value().len(), 32);
    }
}

mod test_nv_define_space {
    use super::*;

    #[test]
    fn test_nv_define_space_failures() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

        // Create owner nv public.
        let mut owner_nv_index_attributes = NvIndexAttributes(0);
        owner_nv_index_attributes.set_owner_write(true);
        owner_nv_index_attributes.set_owner_read(true);

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Create platform nv public.
        let mut platform_nv_index_attributes = NvIndexAttributes(0);
        platform_nv_index_attributes.set_pp_write(true);
        platform_nv_index_attributes.set_pp_read(true);
        platform_nv_index_attributes.set_platform_create(true);

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Failes because attributes dont match hierarchy auth.
        let _ = context
            .nv_define_space(NvAuth::Platform, None, &owner_nv_public)
            .unwrap_err();

        let _ = context
            .nv_define_space(NvAuth::Owner, None, &platform_nv_public)
            .unwrap_err();
    }

    #[test]
    fn test_nv_define_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500016).unwrap();

        // Create owner nv public.
        let mut owner_nv_index_attributes = NvIndexAttributes(0);
        owner_nv_index_attributes.set_owner_write(true);
        owner_nv_index_attributes.set_owner_read(true);

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Create platform nv public.
        let mut platform_nv_index_attributes = NvIndexAttributes(0);
        platform_nv_index_attributes.set_pp_write(true);
        platform_nv_index_attributes.set_pp_read(true);
        platform_nv_index_attributes.set_platform_create(true);

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let owner_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &owner_nv_public)
            .unwrap();

        let _ = context
            .nv_undefine_space(NvAuth::Owner, owner_nv_index_handle)
            .unwrap();

        // If you see this line fail, you are likely running it against a live TPM.
        // On many TPMs, you will get error 0x00000185, indicating the Platform hierarchy to
        // be unavailable (because the system went to operating system)
        let platform_nv_index_handle = context
            .nv_define_space(NvAuth::Platform, None, &platform_nv_public)
            .unwrap();

        let _ = context
            .nv_undefine_space(NvAuth::Platform, platform_nv_index_handle)
            .unwrap();
    }
}

mod test_nv_undefine_space {
    use super::*;

    #[test]
    fn test_nv_undefine_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500017).unwrap();

        // Create owner nv public.
        let mut owner_nv_index_attributes = NvIndexAttributes(0);
        owner_nv_index_attributes.set_owner_write(true);
        owner_nv_index_attributes.set_owner_read(true);

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let owner_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &owner_nv_public)
            .unwrap();

        // Succedes
        let _ = context
            .nv_undefine_space(NvAuth::Owner, owner_nv_index_handle)
            .unwrap();
    }
}

mod test_nv_write {
    use super::*;

    #[test]
    fn test_nv_write() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500018).unwrap();

        // Create owner nv public.
        let mut owner_nv_index_attributes = NvIndexAttributes(0);
        owner_nv_index_attributes.set_owner_write(true);
        owner_nv_index_attributes.set_owner_read(true);

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let owner_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &owner_nv_public)
            .unwrap();

        // Use owner authorization
        let write_result = context.nv_write(
            NvAuth::Owner.into(),
            owner_nv_index_handle,
            &MaxNvBuffer::try_from([1, 2, 3, 4, 5, 6, 7].to_vec()).unwrap(),
            0,
        );

        let _ = context
            .nv_undefine_space(NvAuth::Owner, owner_nv_index_handle)
            .unwrap();

        if let Err(e) = write_result {
            assert!(false, "Failed to perform nv write: {}", e);
        }
    }
}

mod test_nv_read_public {
    use super::*;

    #[test]
    fn test_nv_read_public() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500019).unwrap();

        let mut nv_index_attributes = NvIndexAttributes(0);
        nv_index_attributes.set_owner_write(true);
        nv_index_attributes.set_owner_read(true);

        let expected_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &expected_nv_public)
            .unwrap();

        let read_public_result = context.nv_read_public(nv_index_handle);

        let _ = context
            .nv_undefine_space(NvAuth::Owner, nv_index_handle)
            .unwrap();

        // Report error
        if let Err(e) = read_public_result {
            assert!(false, "Failed to read public of nv index: {}", e);
        }

        // Check result.
        let (actual_nv_public, _name) = read_public_result.unwrap();
        assert_eq!(expected_nv_public, actual_nv_public);
    }
}

mod test_nv_read {
    use super::*;

    #[test]
    fn test_nv_read() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500020).unwrap();

        // Create owner nv public.
        let mut owner_nv_index_attributes = NvIndexAttributes(0);
        owner_nv_index_attributes.set_owner_write(true);
        owner_nv_index_attributes.set_owner_read(true);

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let owner_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &owner_nv_public)
            .unwrap();

        let value = [1, 2, 3, 4, 5, 6, 7];
        let expected_data = MaxNvBuffer::try_from(value.to_vec()).unwrap();

        // Write the data using Owner authorization
        let write_result = context.nv_write(
            AuthHandle::OwnerHandle,
            owner_nv_index_handle,
            &expected_data,
            0,
        );
        // read data using owner authorization
        let read_result = context.nv_read(
            AuthHandle::OwnerHandle,
            owner_nv_index_handle,
            value.len() as u16,
            0,
        );
        let _ = context
            .nv_undefine_space(NvAuth::Owner, owner_nv_index_handle)
            .unwrap();

        // Report error
        if let Err(e) = write_result {
            assert!(false, "Failed to perform nv write: {}", e);
        }
        if let Err(e) = read_result {
            assert!(false, "Failed to read public of nv index: {}", e);
        }

        // Check result.
        let actual_data = read_result.unwrap();
        assert_eq!(expected_data, actual_data);
    }
}

mod test_tr_from_tpm_public {
    use super::*;

    // Need to set the shEnable in the TPMA_STARTUP in order for this to work.
    #[ignore]
    #[test]
    fn test_tr_from_tpm_public_owner_auth() {
        let mut context = create_ctx_without_session();

        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500021).unwrap();

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            let _ = context.nv_undefine_space(NvAuth::Owner, handle).unwrap();
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public.
        let mut nv_index_attributes = NvIndexAttributes(0);
        nv_index_attributes.set_owner_write(true);
        nv_index_attributes.set_owner_read(true);

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        let initial_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, None, &nv_public)
            .unwrap();
        ///////////////////////////////////////////
        // Read the name from the tpm
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        ////////////////////////////////////////////////
        // Close the handle
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .unwrap();
        assert_eq!(handle_to_be_closed, ObjectHandle::from(ESYS_TR_NONE));
        ////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .map_err(|e| -> tss_esapi::Result<ObjectHandle> {
                panic!("tr_from_tpm_public failed: {}", e);
            })
            .unwrap();
        ///////////////////////////////////////////////
        // Get name of the object using the new handle
        let actual_name = context
            .tr_get_name(new_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_get_name"))
            .unwrap();
        //////////////////////////////////////////////
        // Remove undefine the space
        let _ = context
            .nv_undefine_space(NvAuth::Owner, new_nv_index_handle.into())
            .unwrap();

        assert_eq!(expected_name, actual_name);
    }

    #[test]
    fn test_tr_from_tpm_public_password_auth() {
        let mut context = create_ctx_without_session();

        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500022).unwrap();

        let auth = Auth::try_from(vec![
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ])
        .unwrap();

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            context.set_sessions((Some(Session::Password), None, None));
            let _ = context.nv_undefine_space(NvAuth::Owner, handle).unwrap();
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public.
        let mut nv_index_attributes = NvIndexAttributes(0);
        nv_index_attributes.set_auth_write(true);
        nv_index_attributes.set_auth_read(true);

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Define space
        //
        // Set password authorization when creating the space.
        context.set_sessions((Some(Session::Password), None, None));
        let initial_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, Some(&auth), &nv_public)
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Read the name from the tpm
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Close the esys handle (remove all meta data).
        //
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .unwrap();
        assert_eq!(handle_to_be_closed, ObjectHandle::from(ESYS_TR_NONE));
        // The value of the handle_to_be_closed will be set to a 'None' handle
        // if the operations was successful.

        ///////////////////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        //
        // The handle is gone so if this fails it is not
        // possible to remove the defined space.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .map_err(|e| -> tss_esapi::Result<ObjectHandle> {
                panic!("tr_from_tpm_public failed: {}", e);
            })
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Get name of the object using the new handle
        //
        let actual_name = context
            .tr_get_name(new_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_get_name"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Remove undefine the space
        //
        // Set password authorization
        context.set_sessions((Some(Session::Password), None, None));
        let _ = context
            .nv_undefine_space(NvAuth::Owner, new_nv_index_handle.into())
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Check that we got the correct name
        //
        assert_eq!(expected_name, actual_name);
    }

    #[test]
    fn read_from_retrieved_handle_using_password_authorization() {
        let mut context = create_ctx_without_session();

        let nv_index_tpm_handle = NvIndexTpmHandle::new(0x01500023).unwrap();

        let auth = Auth::try_from(vec![
            10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
        ])
        .unwrap();

        // closure for cleaning up if a call fails.
        let cleanup = |context: &mut Context,
                       e: tss_esapi::Error,
                       handle: NvIndexHandle,
                       fn_name: &str|
         -> tss_esapi::Error {
            // Set password authorization
            context.set_sessions((Some(Session::Password), None, None));
            let _ = context.nv_undefine_space(NvAuth::Owner, handle).unwrap();
            panic!("{} failed: {}", fn_name, e);
        };

        // Create nv public. Only use auth for write.
        let mut nv_index_attributes = NvIndexAttributes(0);
        nv_index_attributes.set_auth_write(true);
        nv_index_attributes.set_auth_read(true);

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index_tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Define space
        //
        // Set password authorization when creating the space.
        context.set_sessions((Some(Session::Password), None, None));
        let initial_nv_index_handle = context
            .nv_define_space(NvAuth::Owner, Some(&auth), &nv_public)
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Read the name from the tpm
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, initial_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Write data to created index.
        //
        // When the write succedes the attributes will change
        // and there for the name will change.
        let expected_data = MaxNvBuffer::try_from(vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
        .unwrap();
        context.set_sessions((Some(Session::Password), None, None));
        context
            .nv_write(
                initial_nv_index_handle.into(),
                initial_nv_index_handle,
                &expected_data,
                0,
            )
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_write"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Read the new name that have been calculated after the write.
        //
        // No password authorization.
        context.clear_sessions();
        let (_expected_nv_public, expected_name) = context
            .nv_read_public(initial_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "nv_read_public"))
            .unwrap();
        assert_ne!(initial_name, expected_name);
        ///////////////////////////////////////////////////////////////
        // Close the esys handle (remove all meta data).
        //
        let mut handle_to_be_closed: ObjectHandle = initial_nv_index_handle.into();
        context
            .tr_close(&mut handle_to_be_closed)
            .map_err(|e| cleanup(&mut context, e, initial_nv_index_handle, "tr_close"))
            .unwrap();
        assert_eq!(handle_to_be_closed, ObjectHandle::NoneHandle);
        // The value of the handle_to_be_closed will be set to a 'None' handle
        // if the operations was successful.

        ///////////////////////////////////////////////////////////////
        // Make Esys create a new ObjectHandle from the
        // data in the TPM.
        //
        // The handle is gone so if this fails it is not
        // possible to remove the defined space.
        let new_nv_index_handle = context
            .tr_from_tpm_public(nv_index_tpm_handle.into())
            .map_err(|e| -> tss_esapi::Result<ObjectHandle> {
                panic!("tr_from_tpm_public failed: {}", e);
            })
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Get name of the object using the new handle
        //
        let actual_name = context
            .tr_get_name(new_nv_index_handle)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_get_name"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Call nv_read to get data from nv_index.
        //

        // Set authorization for the retrieved handle
        context
            .tr_set_auth(new_nv_index_handle, &auth)
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "tr_set_auth"))
            .unwrap();
        // read the data
        context.set_sessions((Some(Session::Password), None, None));
        let actual_data = context
            .nv_read(
                new_nv_index_handle.into(),
                new_nv_index_handle.into(),
                32,
                0,
            )
            .map_err(|e| cleanup(&mut context, e, new_nv_index_handle.into(), "nv_read"))
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // Remove undefine the space
        //
        // Set password authorization
        context.set_sessions((Some(Session::Password), None, None));
        let _ = context
            .nv_undefine_space(NvAuth::Owner, new_nv_index_handle.into())
            .unwrap();
        ///////////////////////////////////////////////////////////////
        // The name will have changed
        //
        assert_eq!(expected_name, actual_name);
        assert_eq!(expected_data, actual_data);
    }
}
