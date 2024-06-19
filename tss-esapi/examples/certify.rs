// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * Certification (also referred to as attestation) is the process of validating a key adheres
 * to a promised set of properties. This validation is performed by a cryptographic attestation
 * to provide strong evidence of the properties. This certification is built through a chain of
 * trust.
 *
 * In this example, we will show you how to build that trust chain allowing you to certify
 * objects in a remote TPM.
 *
 * The root of trust in this process is the TPM's endorsement key (EK). This is a key that is
 * embedded into the TPM during manufacturing, or by the platform owner post deployment. This
 * EK allows us to identify that the make and model of the TPM is trustworthy, or that the TPM
 * has been configured by a provisioning process that we trust.
 *
 * The TPM can then enroll an Attestation Key (AIK). This AIK and the EK are both supplied to
 * an authority that validates properties of the EK. If the EK is considered trustworthy, then
 * a challenge is encrypted against the pair of AIK and EK.
 *
 * If the TPM can decrypt this challenge, this proves that both that AIK *and* that EK are both
 * present and loaded simultaneously on the same TPM. In isolation, the AIK or the EK themselves
 * could not decrypt the challenge. This creates the chain between the EK and the AIK such that
 * our authority can now trust the AIK.
 *
 * When the TPM wishes to create or enroll other objects in the future these can have their
 * public structure certified by the AIK. Since our authority has validated the EK/AIK are from
 * a trustworthy source, and our AIK is certifying this public structure, this implies that
 * flags within that public structure are trustworthy. An example of a flag we may wish to validate
 * is `fixedParent` which ensures that the related private key is stored within only that precise
 * TPM.
 *
 * An example of this is the public flag `encrypted_duplication`. If this flag was set on
 * a public object without certification, since we have no trust chain to the TPM the key
 * resides on then we do not know if this flag will be enforced strictly or not - the TPM
 * could be a software TPM where the key could be extracted at any time.
 *
 * However if our object is certified, then we know that the TPM will correctly enforce
 * flags such as `encrypted_duplication` giving us strong assurances about how that private
 * key will be handled.
 *
 *
 * The following diagram demonstrates the process required to create our AIK trust chain and
 * then to certify a key.
 *
 * The Authority in this process does not require a TPM - for brevity we use one in this example
 * but it is possible to perform this certification without a TPM on the authority.
 *
 *
 *                         ┌────────────────────────────────┐                       ┌───────────────────────┐
 *                         │ TPM                            │                       │  Authority            │
 *                         │  ┌──────────────────────────┐  │                       │                       │
 *                         │  │                          │  │                       │                       │
 *  Load EK Template────▶  │  │        EK Handle         │──┼─────Send EK Public────┼────▶  Verify EK       │
 *                         │  │                          │  │                       │           │           │
 *                         │  └──────────────────────────┘  │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │  ┌──────────────────────────┐  │                       │           ▼           │
 *                         │  │                          │  │                       │                       │
 *      Create AIK───────▶ │  │        AIK Handle        │──┼────Send AIK Public────┼▶  Derive AIK Name     │
 *                         │  │                          │  │                       │           │           │
 *                         │  └──────────────────────────┘  │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           ▼           │
 *                         │                                │                       │   Make Credential     │
 *                         │                                │                       │ Encrypt to EK + AIK   │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │     Send Encrypted    │           │           │
 *                         │      Activate Credential ◀─────┼────────Challenge──────┼───────────┘           │
 *                         │                │               │                       │                       │
 *                         │   ┌──────────────────────────┐ │                       │                       │
 *                         │   │                          │ │                       │                       │
 *                         │   │   Decrypted Challenge    │ │                       │                       │
 *                         │   │                          │ │                       │                       │
 *                         │   └──────────────────────────┘ │                       │                       │
 *                         │                 │              │                       │                       │
 *                         │                 └──────────────┼───────────────────────┼▶  Verify Challenge    │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           │           │
 *                         │                                │                       │           ▼           │
 *                         │                                │                       │ AIK is legitimate!!   │
 *                         │                                │                       │                       │
 *                         │                                │                       │                       │
 *      Load another key  ─┼───▶ Certify Object with AIK    │                       │                       │
 *                         │                │               │                       │                       │
 *                         │                │               │                       │                       │
 *                         │                ▼               │                       │                       │
 *                         │  ┌──────────────────────────┐  │                       │                       │
 *                         │  │                          │  │                       │   Verify Attestation  │
 *                         │  │       Attestation        │──┼───────────────────────┼─▶    is from AIK      │
 *                         │  │                          │  │                       │                       │
 *                         │  └──────────────────────────┘  │                       │                       │
 *                         └────────────────────────────────┘                       └───────────────────────┘
 *
 */

use tss_esapi::{
    abstraction::{
        ak::{create_ak, load_ak},
        ek::{create_ek_public_from_default_template, retrieve_ek_pubcert},
        AsymmetricAlgorithmSelection,
    },
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, KeyHandle, SessionHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
        reserved_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        Data, Digest, EccPoint, EccScheme, HashScheme, MaxBuffer, PublicBuilder,
        PublicEccParametersBuilder, SignatureScheme, SymmetricCipherParameters,
        SymmetricDefinition, SymmetricDefinitionObject,
    },
    traits::Marshall,
    Context, TctiNameConf,
};

use std::convert::{TryFrom, TryInto};

fn main() {
    env_logger::init();
    // Create a pair of TPM's contexts - It's not "perfect" but it's what we will use
    // to represent the two TPM's in our test.
    //
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager. You must use a resource managed TPM for this example
    // as using the tpm directly (such as /dev/tpm0) can cause a deadlock.
    let mut context_1 = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    let mut context_2 = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    // First we need the endorsement key. This is bound to the manufacturer of the TPM
    // and will serve as proof that the TPM is trustworthy.

    // Depending on your TPM, it may support different algorithms. Rsa2048 and Ecc384
    // are common endorsement key algorithms.
    //
    // Remember, the Hash alg in many cases has to match the key type, especially
    // with ecdsa.

    // == RSA
    // let ek_alg = AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::RsaPss;
    // let sig_scheme = SignatureScheme::RsaPss {
    //     scheme: HashScheme::new(hash_alg),
    // };

    // == ECDSA P384
    let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384);
    let hash_alg = HashingAlgorithm::Sha384;
    let sign_alg = SignatureSchemeAlgorithm::EcDsa;
    let sig_scheme = SignatureScheme::EcDsa {
        scheme: HashScheme::new(hash_alg),
    };

    // == ECDSA P256
    // let ek_alg = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    // let hash_alg = HashingAlgorithm::Sha256;
    // let sign_alg = SignatureSchemeAlgorithm::EcDsa;
    // let sig_scheme = SignatureScheme::EcDsa {
    //    scheme: HashScheme::new(hash_alg),
    // };

    // If you wish to see the EK cert, you can fetch it's X509 DER here.
    let ek_pubcert = retrieve_ek_pubcert(&mut context_1, ek_alg).unwrap();

    // Alternately on the CLI you can view the certificate with:
    // # tpm2_getekcertificate | openssl x509 -inform DER -noout -text

    eprintln!("ek_pubcert der: {:x?}", ek_pubcert);

    // Retrieve the EK public template that allows us to access a handle to the EK
    let ek_template = create_ek_public_from_default_template(ek_alg, None).unwrap();

    // Get the EK handle by loading our template.
    let ek_handle = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_template, None, None, None, None)
        })
        .expect("Failed to load ek_template")
        .key_handle;

    // Get the specific public value of our EK
    let (ek_public, _name, _qualified_name) = context_1
        .read_public(ek_handle)
        .expect("Failed to read ek_public");

    // Now, create our AIK. The AIK in theory does not need to be in the same hierarchy as
    // the EK, it only needs to be in the same *TPM*. However in reality, using the create_ak
    // and load_ak functions only works if you use the key in the endorsement hierarchy.
    let ak_create_result = create_ak(
        &mut context_1,
        ek_handle,
        hash_alg,
        ek_alg,
        sign_alg,
        None,
        None,
    )
    .expect("Failed to create attestation key");

    let ak_public = ak_create_result.out_public.clone();

    // For later, we'll load the AIK now and save it's context.
    let ak_handle = load_ak(
        &mut context_1,
        ek_handle,
        None,
        ak_create_result.out_private,
        ak_create_result.out_public,
    )
    .expect("Failed to load attestation key");

    let ak_context = context_1
        .execute_with_nullauth_session(|ctx| ctx.context_save(ak_handle.into()))
        .expect("Failed to save ak context");

    context_1
        .flush_context(ak_handle.into())
        .expect("Unable to flush ak_handle");

    // For now to save resources, we save the ek context.
    let ek_context = context_1
        .execute_with_nullauth_session(|ctx| ctx.context_save(ek_handle.into()))
        .expect("Failed to save ek context");

    context_1
        .flush_context(ek_handle.into())
        .expect("Unable to flush ek_handle");

    // ================================================================================
    // At this point we have what we need: The EK X509 DER, EK Public and AIK public for the
    // certifying authority. They are in the corresponding variables right now.

    // ek_pubcert
    // ek_public
    // ak_public

    // Here, the authority should validate that the EK X509 DER is from a trusted authority,
    // the the EK public key matches the public key from EK X509 DER.

    // The authority should also validate the AIK has valid properties such as fixedParent
    // and fixedTPM so that we can assert the AIK is bound to this single device, and that
    // this is a restricted key which does not allow signature of external inputs.

    // In our example, we will be taking the trust approach known as "yolo" by verifying none
    // of these details. This is considered unwise in production. Do not be like me.

    // Load the AIK public, and derive it's "name". This will be used as part of the
    // challenge encryption.
    let (_public, ak_name, _qualified_name) = context_2
        .execute_with_nullauth_session(|ctx| {
            let ak_handle = ctx.load_external_public(ak_public.clone(), Hierarchy::Null)?;
            let r = ctx.read_public(ak_handle);
            ctx.flush_context(ak_handle.into())?;
            r
        })
        .expect("Unable to read AIK public");

    let ak_public_object_attributes = ak_public.object_attributes();
    assert!(ak_public_object_attributes.fixed_tpm());
    assert!(ak_public_object_attributes.fixed_parent());
    assert!(ak_public_object_attributes.restricted());

    // We now create our challenge that we will encrypt. We use 16 bytes (128bit) for
    // a sufficiently random value.
    //
    // Importantly, the authority MUST persist this value for verification in a future
    // step. This value MUST NOT be disclosed!
    let challenge = context_2
        .get_random(16)
        .expect("Unable to access random data.");

    // Now we load the ek_public, and create our encrypted challenge.
    let (idobject, encrypted_secret) = context_2
        .execute_with_nullauth_session(|ctx| {
            let ek_handle = ctx.load_external_public(ek_public, Hierarchy::Null)?;
            let r = ctx.make_credential(ek_handle, challenge.clone(), ak_name);
            ctx.flush_context(ek_handle.into())?;
            r
        })
        .expect("Unable to create encrypted challenge");

    // Great! We now have the encrypted challenges to be returned to the first TPM.

    // ================================================================================
    // The values idobject and encrypted_secret are securely returned to the first TPM.
    // We now load and decrypt these to prove that the AIK must be loaded in the same
    // TPM that also contains this EK. This is how the trust chain is built - if we
    // only had the EK or the AIK we would be unable to decrypt the challenge, we
    // require both to be present.
    let ek_handle = context_1
        .context_load(ek_context)
        .expect("Failed to restore EK context");

    let ak_handle = context_1
        .context_load(ak_context)
        .expect("Failed to restore AIK context");

    // We need two sessions here. One session to authenticate the EK, and one
    // for the AIK
    let session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap()
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context_1
        .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        .unwrap();

    // Create a session that is capable of performing endorsements.
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    let policy_auth_session = context_1
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

    context_1
        .tr_sess_set_attributes(
            policy_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let _ = context_1
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

    let response = context_1
        .execute_with_sessions((Some(session), Some(policy_auth_session), None), |ctx| {
            ctx.activate_credential(
                ak_handle.into(),
                ek_handle.into(),
                idobject,
                encrypted_secret,
            )
        })
        .unwrap();

    // Unload the sessions we used.
    context_1.clear_sessions();

    context_1
        .flush_context(SessionHandle::from(session).into())
        .expect("Failed to clear session");

    context_1
        .flush_context(SessionHandle::from(policy_auth_session).into())
        .expect("Failed to clear policy_auth_session");

    // At this point we no longer need the EK loaded. We want to keep the AIK loaded for
    // the certify operation we will perform shortly.
    context_1
        .flush_context(ek_handle)
        .expect("Failed to unload EK");

    context_1.clear_sessions();

    // ================================================================================
    // The response is now sent back to the authority which can verify the response
    // is identical to challenge. If this is the case, the authority can now persist
    // the AIK public for use in future certify operations.
    assert_eq!(challenge, response);

    // ================================================================================
    // Now begin certifying a new key.

    // Create the key we wish to certify.
    let key_handle = create_key(&mut context_1);

    context_1.clear_sessions();

    // This is added to the "extra_data" field of the attestation object. Some uses of this
    // include in Webauthn where this qualifying data contains the sha256 hash of other data
    // that is being authenticated in the operation.
    let qualifying_data: Data = vec![1, 2, 3, 4, 5, 6, 7, 8].try_into().unwrap();

    let session = context_1
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .unwrap()
        .unwrap();

    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();

    context_1
        .tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
        .unwrap();

    // Create a session to authenticate to the AIK.
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();

    let aik_auth_session = context_1
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

    context_1
        .tr_sess_set_attributes(
            aik_auth_session,
            session_attributes,
            session_attributes_mask,
        )
        .unwrap();

    let (attest, signature) = context_1
        .execute_with_sessions(
            (
                // The first session authenticates the "object to certify".
                Some(session),
                // This authenticates the attestation key.
                Some(aik_auth_session),
                None,
            ),
            |ctx| {
                ctx.certify(
                    key_handle.into(),
                    ak_handle.into(),
                    qualifying_data,
                    sig_scheme,
                )
            },
        )
        .unwrap();

    // Clear the sessions again
    context_1
        .flush_context(SessionHandle::from(session).into())
        .expect("Failed to clear session");

    context_1
        .flush_context(SessionHandle::from(aik_auth_session).into())
        .expect("Failed to clear policy_auth_session");

    println!("attest: {:?}", attest);
    println!("signature: {:?}", signature);

    // ================================================================================
    // Now back on our certifying authority, we want to assert that the attestation we
    // received really did come from this TPM. We can use the AIK to demonstrate this
    // linkage, to trust that the object must come from a valid TPM that we trust to
    // behave in a certain manner.
    //
    // Depending on your use case, you may need to validate other properties around
    // the attestation signature.

    // First, load the public from the aik
    let ak_handle = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.load_external_public(
                ak_public,
                // We put it into the null hierarchy as this is ephemeral.
                Hierarchy::Null,
            )
        })
        .expect("Failed to load aik public");

    let attest_data: MaxBuffer = attest
        .marshall()
        .expect("Unable to marshall")
        .try_into()
        .expect("Data too large");

    let (attest_digest, _ticket) = context_2
        .execute_with_nullauth_session(|ctx| {
            // Important to note that this MUST match the ak hash algorithm
            ctx.hash(attest_data, hash_alg, Hierarchy::Null)
        })
        .expect("Failed to digest attestation output");

    let verified_ticket = context_2
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
