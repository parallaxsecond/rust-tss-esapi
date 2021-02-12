// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_verify_signature {
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
        structures::{Auth, Digest},
        tss2_esys::{TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
        utils::{AsymSchemeUnion, Signature, SignatureData},
    };

    #[test]
    fn test_verify_signature() {
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
    fn test_verify_wrong_signature() {
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
    fn test_verify_wrong_signature_2() {
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
    fn test_verify_wrong_signature_3() {
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

mod test_sign {
    use crate::common::{create_ctx_with_session, signing_key_pub, HASH};
    use std::convert::{TryFrom, TryInto};
    use tss_esapi::{
        constants::tss::{TPM2_ALG_NULL, TPM2_RH_NULL, TPM2_ST_HASHCHECK},
        interface_types::resource_handles::Hierarchy,
        structures::{Auth, Digest},
        tss2_esys::{TPMT_SIG_SCHEME, TPMT_TK_HASHCHECK},
    };

    #[test]
    fn test_sign() {
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
