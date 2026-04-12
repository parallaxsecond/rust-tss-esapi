// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_ec_ephemeral {
    use crate::common::create_ctx_without_session;
    use tss_esapi::interface_types::ecc::EccCurve;

    #[test]
    fn test_ec_ephemeral() {
        let mut context = create_ctx_without_session();
        let (q_point, counter) = context.ec_ephemeral(EccCurve::NistP256).unwrap();
        assert!(q_point.x().len() > 0);
        assert!(counter > 0);
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
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

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
            .unwrap();

        let object_attributes = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_decrypt(false)
            .with_sign_encrypt(true)
            .with_restricted(false)
            .build()
            .unwrap();

        let public = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(object_attributes)
            .with_ecc_parameters(ecc_parms)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .unwrap();

        let key_handle = context
            .create_primary(Hierarchy::Owner, public, Some(key_auth), None, None, None)
            .unwrap()
            .key_handle;

        let (_k, _l, _e, counter) = context.commit(key_handle, None, None, None).unwrap();
        assert!(counter > 0);
    }
}
