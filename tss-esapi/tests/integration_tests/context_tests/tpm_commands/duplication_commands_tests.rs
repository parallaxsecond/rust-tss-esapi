// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_duplicate {
    use crate::common::{create_ctx_with_session, create_ctx_without_session};
    use std::convert::TryFrom;
    use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    use tss_esapi::constants::{tss::TPM2_CC_Duplicate, SessionType};
    use tss_esapi::handles::ObjectHandle;
    use tss_esapi::interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    };
    use tss_esapi::structures::SymmetricDefinition;
    use tss_esapi::structures::{
        EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
        PublicEccParametersBuilder, SymmetricDefinitionObject,
    };

    #[test]
    fn test_duplicate() {
        let mut context = create_ctx_without_session();

        let trial_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");

        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(trial_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_auth_value(policy_session)
            .expect("Policy auth value");

        context
            .policy_command_code(policy_session, TPM2_CC_Duplicate)
            .expect("Policy command code");

        let digest = context
            .policy_get_digest(policy_session)
            .expect("Could retrieve digest");

        drop(context);
        let mut context = create_ctx_with_session();

        let parent_object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(false)
            .with_restricted(true)
            .build()
            .expect("Attributes to be valid");

        let public_parent = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(parent_object_attributes)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(true)
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(&EccPoint::default())
            .build()
            .expect("public to be valid");

        let parent_of_object_to_duplicate_handle = context
            .create_primary(Hierarchy::Owner, &public_parent, None, None, None, None)
            .unwrap()
            .key_handle;

        // Fixed TPM and Fixed Parent should be "false" for an object
        // to be elligible for duplication
        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(false)
            .with_fixed_parent(false)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(true)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Attributes to be valid");

        let public_child = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_auth_policy(&digest)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_is_signing_key(false)
                    .with_is_decryption_key(true)
                    .with_restricted(false)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .build()
                    .expect("Params to be valid"),
            )
            .with_ecc_unique_identifier(&EccPoint::default())
            .build()
            .expect("public to be valid");

        let result = context
            .create(
                parent_of_object_to_duplicate_handle,
                &public_child,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let object_to_duplicate_handle: ObjectHandle = context
            .load(
                parent_of_object_to_duplicate_handle,
                result.out_private.clone(),
                &result.out_public,
            )
            .unwrap()
            .into();

        let new_parent_handle: ObjectHandle = context
            .create_primary(Hierarchy::Owner, &public_parent, None, None, None, None)
            .unwrap()
            .key_handle
            .into();

        context.set_sessions((None, None, None));

        let policy_auth_session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .expect("Start auth session failed")
            .expect("Start auth session returned a NONE handle");
        let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
            SessionAttributesBuilder::new()
                .with_decrypt(true)
                .with_encrypt(true)
                .build();
        context
            .tr_sess_set_attributes(
                policy_auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

        let policy_session = PolicySession::try_from(policy_auth_session)
            .expect("Failed to convert auth session into policy session");

        context
            .policy_auth_value(policy_session)
            .expect("Policy auth value works");

        context
            .policy_command_code(policy_session, TPM2_CC_Duplicate)
            .unwrap();
        context.set_sessions((Some(policy_auth_session), None, None));

        let (data, private, secret) = context
            .duplicate(
                object_to_duplicate_handle,
                new_parent_handle,
                None,
                SymmetricDefinitionObject::Null,
            )
            .unwrap();
        eprintln!("D: {:?}, P: {:?}, S: {:?}", data, private, secret);
    }
}
