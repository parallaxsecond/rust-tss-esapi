// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_verify_signature {
    use serial_test::serial;
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Hierarchy},
        structures::{Auth, Digest, PublicKeyRsa, RsaSignature, Signature, SignatureScheme},
    };

    #[test]
    #[serial]
    fn test_verify_signature() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let signature = context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                None,
            )
            .unwrap();

        context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .unwrap();
    }

    #[test]
    #[serial]
    fn test_verify_wrong_signature() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let mut signature = context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                None,
            )
            .unwrap();

        if let Signature::RsaSsa(rsa_signature) = &mut signature {
            let mut key_data: Vec<u8> = rsa_signature.signature().as_bytes().to_vec();
            key_data.reverse();
            *rsa_signature = RsaSignature::create(
                rsa_signature.hashing_algorithm(),
                PublicKeyRsa::try_from(key_data).expect("Failed to create oublic key rsa,"),
            )
            .expect("Failed to create signature");
        }

        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    #[serial]
    fn test_verify_wrong_signature_2() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0xab; 500])
                    .expect("Failed to create public key rsa structure"),
            )
            .expect("Failed to create RSA SSA signature"),
        );

        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }

    #[test]
    #[serial]
    fn test_verify_wrong_signature_3() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let signature = Signature::RsaSsa(
            RsaSignature::create(
                HashingAlgorithm::Sha256,
                PublicKeyRsa::try_from(vec![0; 0])
                    .expect("Failed to create public key rsa structure"),
            )
            .expect("Failed to create RSA SSA signature"),
        );
        assert!(context
            .verify_signature(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                signature,
            )
            .is_err());
    }
}

mod test_sign {
    use serial_test::serial;
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::TryFrom;
    use tss_esapi::{
        interface_types::{
            algorithm::RsaSchemeAlgorithm, key_bits::RsaKeyBits, reserved_handles::Hierarchy,
        },
        structures::{Auth, Digest, RsaExponent, RsaScheme, SignatureScheme},
        error::TpmFormatOneResponseCode, error::ArgumentNumber::Parameter,
        constants::TpmFormatOneError::Size, error::TpmResponseCode,
        ReturnCode,
    };

    use {
        digest::Digest as _,
        signature::{DigestVerifier, Keypair, Signer, Verifier},
        std::sync::Mutex,
    };

    #[cfg(feature = "p256")]
    use {
        p256::{ecdsa::Signature, NistP256},
        tss_esapi::{
            abstraction::EcSigner,
            interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve},
            structures::{EccScheme, HashScheme},
            utils,
        },
    };

    #[cfg(feature = "rsa")]
    use {
        rsa::{pkcs1v15, pss},
        tss_esapi::abstraction::{RsaPkcsSigner, RsaPssSigner},
    };

    #[test]
    #[serial]
    fn test_sign() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        context
            .sign(
                key_handle,
                Digest::try_from(HASH[..32].to_vec()).unwrap(),
                SignatureScheme::Null,
                None,
            )
            .unwrap();
    }

    #[test]
    #[serial]
    fn test_sign_empty_digest() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        context
            .sign(
                key_handle,
                Digest::try_from(Vec::<u8>::new()).unwrap(),
                SignatureScheme::Null,
                None,
            )
            .unwrap_err();
    }

    #[test]
    #[serial]
    fn test_sign_large_digest() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        assert_eq!(context
                   .sign(
                       key_handle,
                       Digest::try_from([0xbb; 40].to_vec()).unwrap(),
                       SignatureScheme::Null,
                       None,
                   )
                   .unwrap_err(),
                   tss_esapi::Error::TssError(
                       ReturnCode::Tpm(
                           TpmResponseCode::FormatOne(TpmFormatOneResponseCode::new(
                               Size, Parameter(1)
                           )))));
    }

    #[cfg(feature = "p256")]
    #[test]
    #[serial]
    fn test_sign_signer() {
        let public = utils::create_unrestricted_signing_ecc_public(
            EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
            EccCurve::NistP256,
        )
        .expect("Create ecc public struct");

        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(Hierarchy::Owner, public, Some(key_auth), None, None, None)
            .unwrap()
            .key_handle;

        let mut random = vec![0u8; 47];
        getrandom::getrandom(&mut random).unwrap();

        let signer = EcSigner::<NistP256, _>::new((Mutex::new(&mut context), key_handle)).unwrap();
        let verifying_key = signer.verifying_key();
        let signature: Signature = signer.sign(&random);

        verifying_key.verify(&random, &signature).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    #[serial]
    fn test_sign_signer_rsa_pkcs() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                signing_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;

        let mut payload = vec![0u8; 47];
        getrandom::getrandom(&mut payload).unwrap();

        let signer =
            RsaPkcsSigner::<_, sha2::Sha256>::new((Mutex::new(&mut context), key_handle)).unwrap();
        let verifying_key = signer.verifying_key();
        let signature: pkcs1v15::Signature = signer.sign(&payload);

        verifying_key.verify(&payload, &signature).unwrap();

        let d = sha2::Sha256::new_with_prefix(&payload);
        verifying_key.verify_digest(d, &signature).unwrap();
    }

    #[cfg(feature = "rsa")]
    #[test]
    #[serial]
    fn test_sign_signer_rsa_pss() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let rsa_pss = utils::create_unrestricted_signing_rsa_public(
            RsaScheme::create(RsaSchemeAlgorithm::RsaPss, Some(HashingAlgorithm::Sha256))
                .expect("Failed to create RSA scheme"),
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )
        .expect("Failed to create an unrestricted signing rsa public structure");

        let key_handle = context
            .create_primary(Hierarchy::Owner, rsa_pss, Some(key_auth), None, None, None)
            .unwrap()
            .key_handle;

        let mut payload = vec![0u8; 47];
        getrandom::getrandom(&mut payload).unwrap();

        let signer =
            RsaPssSigner::<_, sha2::Sha256>::new((Mutex::new(&mut context), key_handle)).unwrap();
        let verifying_key = signer.verifying_key();
        let signature: pss::Signature = signer.sign(&payload);

        verifying_key.verify(&payload, &signature).unwrap();

        let d = sha2::Sha256::new_with_prefix(&payload);
        verifying_key.verify_digest(d, &signature).unwrap();
    }
}
