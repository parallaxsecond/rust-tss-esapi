// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_policy_signed {
    use crate::common::{create_ctx_with_session, signing_key_pub};
    use std::{
        convert::{TryFrom, TryInto},
        time::Duration,
    };
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        interface_types::resource_handles::Hierarchy,
        structures::{Digest, Nonce},
        utils::{AsymSchemeUnion, Signature, SignatureData},
    };
    #[test]
    fn test_policy_signed() {
        let mut context = create_ctx_with_session();

        let key_handle = context
            .create_primary(Hierarchy::Owner, &signing_key_pub(), None, None, None, None)
            .unwrap()
            .key_handle;

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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let nonce_tpm = Nonce::try_from(vec![1, 2, 3]).expect("Failed to convert data into Nonce");
        let cp_hash_a =
            Digest::try_from(vec![1, 2, 3]).expect("Failed to convert data into Digest");
        let policy_ref = Nonce::try_from(vec![1, 2, 3]).expect("Failed to convert data into Nonce");
        let signature = Signature {
            scheme: AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            signature: SignatureData::RsaSignature(vec![0xab; 32]),
        };

        context
            .policy_signed(
                trial_session,
                key_handle.try_into().unwrap(),
                nonce_tpm,
                cp_hash_a,
                policy_ref,
                Some(Duration::from_secs(3600)),
                signature,
            )
            .expect("Call to policy_signed failed");
    }
}

mod test_polic_secret {
    use crate::common::create_ctx_with_session;
    use std::{convert::TryFrom, time::Duration};
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        handles::AuthHandle,
        structures::{Digest, Nonce},
    };
    #[test]
    fn test_policy_secret() {
        let mut context = create_ctx_with_session();

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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let nonce_tpm = Nonce::try_from(vec![1, 2, 3]).unwrap();
        let cp_hash_a = Digest::try_from(vec![1, 2, 3]).unwrap();
        let policy_ref = Nonce::try_from(vec![1, 2, 3]).unwrap();

        context
            .policy_secret(
                trial_session,
                AuthHandle::Endorsement,
                nonce_tpm,
                cp_hash_a,
                policy_ref,
                Some(Duration::from_secs(3600)),
            )
            .unwrap();
    }
}

mod test_policy_or {
    use crate::common::{create_ctx_without_session, get_pcr_policy_digest};
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        structures::DigestList,
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

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
}

mod test_policy_pcr {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        interface_types::resource_handles::Hierarchy,
        structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot},
    };

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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

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

mod test_policy_locality {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context.policy_locality(trial_session, 3).unwrap();
    }
}

mod test_policy_command_code {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            tss::TPM2_CC_Unseal,
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context
            .policy_command_code(trial_session, TPM2_CC_Unseal)
            .unwrap();
    }
}

mod test_policy_physical_presence {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context.policy_physical_presence(trial_session).unwrap();
    }
}

mod test_policy_cp_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        structures::Digest,
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_cp_hash(trial_session, &test_dig).unwrap();
    }
}

mod test_policy_name_hash {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        structures::Digest,
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let test_dig = Digest::try_from(vec![
            252, 200, 17, 232, 137, 217, 130, 51, 54, 22, 184, 131, 2, 134, 99, 130, 175, 216, 159,
            174, 203, 165, 35, 19, 187, 56, 167, 208, 3, 128, 11, 12,
        ])
        .unwrap();

        // There should be no errors setting an Or for a TRIAL session
        context.policy_name_hash(trial_session, &test_dig).unwrap();
    }
}

mod test_policy_authorize {
    use crate::common::{create_ctx_with_session, get_pcr_policy_digest, signing_key_pub};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::{
            algorithm::HashingAlgorithm,
            tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        },
        interface_types::resource_handles::Hierarchy,
        structures::{Auth, MaxBuffer, Nonce},
        tss2_esys::{TPM2B_NONCE, TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
    };
    #[test]
    fn test_policy_authorize() {
        let mut context = create_ctx_with_session();
        let random_digest = context.get_random(16).unwrap();
        let key_auth = Auth::try_from(random_digest.value().to_vec()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                &signing_key_pub(),
                Some(&key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
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
}

mod test_policy_auth_value {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context.policy_auth_value(trial_session).unwrap();
    }
}

mod test_policy_password {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context.policy_password(trial_session).unwrap();
    }
}

mod test_policy_get_digest {
    use crate::common::create_ctx_without_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
        interface_types::resource_handles::Hierarchy,
        structures::{MaxBuffer, PcrSelectionListBuilder, PcrSlot},
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

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

mod test_policy_nv_written {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        attributes::SessionAttributesBuilder,
        constants::{
            algorithm::{Cipher, HashingAlgorithm},
            SessionType,
        },
    };
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
        let (trial_session_attributes, trial_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                trial_session_attributes,
                trial_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        // There should be no errors setting an Or for a TRIAL session
        context.policy_nv_written(trial_session, true).unwrap();
    }
}
