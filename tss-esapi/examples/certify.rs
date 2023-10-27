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
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::AuthSession,
    },
    structures::{
        Data, Digest, EccPoint, EccScheme, HashScheme, MaxBuffer, PublicBuilder,
        PublicEccParametersBuilder, SignatureScheme, SymmetricCipherParameters,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::Marshall,
    Context, TctiNameConf,
};

use std::convert::TryInto;

fn main() {
    env_logger::init();
    // Create a new TPM context. This reads from the environment variable `TPM2TOOLS_TCTI` or `TCTI`
    //
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager.
    let mut context = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    // First create the key that we wish to certify. Note that we create this inside the
    // owner hierachy.
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
    // let sig_scheme = SignatureScheme::EcDsa {
    //     scheme: HashScheme::new(hash_alg),
    // };

    // ⚠️  swtpm doesn't support by default
    // let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::EcDsa;
    // let sig_scheme = SignatureScheme::EcDsa {
    //    scheme: HashScheme::new(hash_alg),
    // };

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

    // Keep the aik_public for later :)
    let ak_public = ak_loadable.out_public.clone();

    // Load it for use.
    let ak_handle = load_ak(
        &mut context,
        ek_handle,
        None,
        ak_loadable.out_private,
        ak_loadable.out_public,
    )
    .unwrap();

    // TODO: Show to to export the AIK as x509/DER so that it can be chained back to the EK
    // so that a remote party can consume the attestation.

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

    // This is added to the "extra_data" field of the attestation object. Some uses of this
    // include in Webauthn where this qualifying data contains the sha256 hash of other data
    // that is being authenticated in the operation.
    let qualifying_data: Data = vec![1, 2, 3, 4, 5, 6, 7, 8].try_into().unwrap();

    let (attest, signature) = context
        .execute_with_sessions(
            (
                // The first session authenticates the "object to certify".
                Some(AuthSession::Password),
                // What does?
                Some(nullauth_session),
                None,
            ),
            |ctx| ctx.certify(key_handle.into(), ak_handle, qualifying_data, sig_scheme),
        )
        .unwrap();

    println!("attest: {:?}", attest);
    println!("signature: {:?}", signature);

    // Now we can verify this attestation.

    // Lets clear our contexts and start fresh.
    drop(context);

    let mut context = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    // First, load the public from the aik
    let ak_handle = context
        .execute_with_nullauth_session(|ctx| {
            ctx.load_external_public(
                ak_public,
                // We put it into the null hierachy as this is ephemeral.
                Hierarchy::Null,
            )
        })
        .expect("Failed to load aik public");

    let attest_data: MaxBuffer = attest
        .marshall()
        .expect("Unable to marshall")
        .try_into()
        .expect("Data too large");

    let (attest_digest, _ticket) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.hash(attest_data, HashingAlgorithm::Sha256, Hierarchy::Null)
        })
        .expect("Failed to digest attestation output");

    let verified_ticket = context
        .execute_with_nullauth_session(|ctx| {
            ctx.verify_signature(ak_handle, attest_digest, signature)
        })
        .expect("Failed to verify attestation");

    println!("verification: {:?}", verified_ticket);
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
