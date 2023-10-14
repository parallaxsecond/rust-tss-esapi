// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to certify a key that is loaded into the TPM.
 */

use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        ek::{create_ek_object, retrieve_ek_pubcert},
        AsymmetricAlgorithmSelection,
    },
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, KeyHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        Data, Digest, EccPoint, EccScheme, HashScheme, KeyedHashScheme, MaxBuffer, PublicBuilder,
        PublicEccParametersBuilder, PublicKeyedHashParameters, SignatureScheme,
        SymmetricCipherParameters, SymmetricDefinition, SymmetricDefinitionObject,
    },
    Context, TctiNameConf,
};

use std::convert::TryFrom;

fn main() {
    // Create a new TPM context. This reads from the environment variable `TPM2TOOLS_TCTI` or `TCTI`
    //
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager.
    let mut context = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    // First create the key that we wish to certify.
    let key_handle = create_key(&mut context);

    // Now setup the endorsement key. Depending on your TPM, it may require
    // different algorithms. Rsa2048 and Ecc384 are common.
    //
    // Remember, the Hash alg in many cases has to match the key type, especially
    // with ecdsa.
    let ek_alg = AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048);
    let hash_alg = HashingAlgorithm::Sha256;
    let sign_alg = SignatureSchemeAlgorithm::RsaPss;
    let sig_scheme = SignatureScheme::RsaPss {
        scheme: HashScheme::new(hash_alg),
    };

    // ⚠️  Appears to be an invalid combination.
    // let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384);
    // let hash_alg = HashingAlgorithm::Sha384;
    // let sign_alg = SignatureSchemeAlgorithm::EcDsa;

    // ⚠️  swtpm doesn't support by default
    // let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::EcDsa;

    // If you wish to see the EK cert, you can fetch it's DER here.
    let ek_pubcert = retrieve_ek_pubcert(&mut context, ek_alg).unwrap();

    eprintln!("ek_pubcert der: {:?}", ek_pubcert);

    // Load the ek object
    let ek_handle = create_ek_object(&mut context, ek_alg, None).unwrap();

    // Now that we have the ek, we can create an aik
    let ak_loadable = create_ak(
        &mut context,
        ek_handle,
        hash_alg,
        ek_alg,
        sign_alg,
        None,
        None,
    )
    .unwrap();

    // Load it for use.
    let ak_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak_loadable.out_private,
        ak_loadable.out_public,
    )
    .unwrap();

    // ⚠️  At this point things start to break down.
    // * Session Confusion
    //   It seems like there are some missing helpers in abstraction to help create the policy auth
    //   session, or how to use it with the other nullauth session. As a result, we pretty much have
    //   to manually craft everything to make this viable.
    // * PolicyFail
    //   Trying to use the session "exactly" as the abstraction code from ak demonstrates results
    //   in policy fail.
    // * Default Ak is restricted
    //   But certify needs qualifying data that requires an unrestricted key.

    // TODO: Show verification of the attestation/signature.

    // TODO: Show to to export the AIK as x509/DER so that it can be chained back to the EK
    // so that a remote party can consume the attestation.

    let policy_auth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Invalid session attributes.")
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let _ = context
        .execute_with_nullauth_session(|ctx| {
            ctx.policy_secret(
                PolicySession::try_from(policy_auth_session).unwrap(),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    let nullauth_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Invalid session attributes.")
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        // Can't set decrypt/encrypt at the same time as the policy session.
        // .with_decrypt(true)
        // .with_encrypt(true)
        .build();
    context
        .tr_sess_set_attributes(
            nullauth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let qualifying_data = Data::default();

    let (attest, signature) = context
        .execute_with_sessions(
            (Some(policy_auth_session), Some(nullauth_session), None),
            |ctx| ctx.certify(key_handle.into(), ak_handle, qualifying_data, sig_scheme),
        )
        .unwrap();
}

fn create_key(context: &mut Context) -> KeyHandle {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let primary = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap();

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // The key is used only for signing.
        .with_sign_encrypt(true)
        .build()
        .expect("Failed to build object attributes");

    let ecc_params = PublicEccParametersBuilder::new_unrestricted_signing_key(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )
    .build()
    .expect("Failed to build ecc params");

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .unwrap();

    context
        .execute_with_nullauth_session(|ctx| {
            let (private, public) = ctx
                .create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))?;
            let key_handle = ctx.load(primary.key_handle, private, public)?;
            // Unload the primary to make space for objects.
            ctx.flush_context(primary.key_handle.into())
                // And return the key_handle.
                .map(|()| key_handle)
        })
        .unwrap()
}
