// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_ec_ephemeral {
    use crate::common::create_ctx_without_session;
    use tss_esapi::interface_types::ecc::EccCurve;

    #[test]
    fn test_ec_ephemeral() {
        let mut context = create_ctx_without_session();
        let (q_point, counter) = context
            .ec_ephemeral(EccCurve::NistP256)
            .expect("Failed to create EC ephemeral key");
        assert!(!q_point.x().is_empty());

        // Call again and verify the counter increments.
        let (_, counter2) = context
            .ec_ephemeral(EccCurve::NistP256)
            .expect("Failed to create second EC ephemeral key");
        assert_eq!(counter2, counter + 1);
    }
}

mod test_commit {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        attributes::ObjectAttributesBuilder,
        interface_types::{
            algorithm::{HashingAlgorithm, PublicAlgorithm},
            ecc::EccCurve,
            reserved_handles::Hierarchy,
        },
        structures::{
            Auth, EccPoint, EccScheme, KeyDerivationFunctionScheme, PublicBuilder,
            PublicEccParametersBuilder,
        },
    };

    #[test]
    fn test_commit() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).expect("Failed to get random bytes");
        let key_auth =
            Auth::from_bytes(random_digest.as_slice()).expect("Failed to create key auth");

        let ecc_parms = PublicEccParametersBuilder::new()
            .with_ecc_scheme(EccScheme::EcDaa(tss_esapi::structures::EcDaaScheme::new(
                HashingAlgorithm::Sha256,
                0,
            )))
            .with_curve(EccCurve::BnP256)
            .with_is_signing_key(true)
            .with_is_decryption_key(false)
            .with_restricted(false)
            .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
            .build()
            .expect("Failed to build ECC parameters");

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .expect("Failed to build object attributes");

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parms)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .expect("Failed to build public key");

        let key_handle = context
            .create_primary(Hierarchy::Owner, public, Some(key_auth), None, None, None)
            .expect("Failed to create primary key")
            .key_handle;

        let (_k, _l, _e, counter) = context
            .commit(key_handle, EccPoint::default(), None, None)
            .expect("Failed to perform ECC commit");

        // Call again and verify the counter increments.
        let (_k2, _l2, _e2, counter2) = context
            .commit(key_handle, EccPoint::default(), None, None)
            .expect("Failed to perform second ECC commit");
        assert_eq!(counter2, counter + 1);
    }
}
