// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to create a storage key that can be duplicated between
 * two TPM's, allowing the child keys to be used between the two.
 * graphically this can be represented as:
 *
 *    ┌────────────────────────┐      ┌────────────────────────┐
 *    │  TPM 1                 │      │  TPM 2                 │
 *    │                        │      │                        │
 *    │   ┌───────────────┐    │      │    ┌───────────────┐   │
 *    │   │   Primary 1   │    │      │    │   Primary 2   │   │
 *    │   └───────────────┘    │      │    └───────────────┘   │
 *    │           │            │      │            ▲           │
 *    │           ▼            │      │            │           │
 *    │   ┌───────────────┐    │      │                        │
 *    │   │  Storage Key  │─ ─ ┼ ─ ─Duplicated To─ ┘           │
 *    │   └───────────────┘    │      │                        │
 *    │           │            │      │                        │
 *    │           ▼            │      │                        │
 *    │    ┌────────────────┐  │      │                        │
 *    │   ┌┴───────────────┐│  │      │                        │
 *    │  ┌┴──────────────┐ ├┘  │      │                        │
 *    │  │  Child Keys   ├─┘   │      │                        │
 *    │  └───────────────┘     │      │                        │
 *    └────────────────────────┘      └────────────────────────┘
 *
 *
 * Since the storage key was duplicated, then the child keys can be loaded to the second
 * tpm as a result.
 *
 *    ┌────────────────────────┐      ┌────────────────────────┐
 *    │  TPM 1                 │      │  TPM 2                 │
 *    │                        │      │                        │
 *    │   ┌───────────────┐    │      │    ┌───────────────┐   │
 *    │   │   Primary 1   │    │      │    │   Primary 2   │   │
 *    │   └───────────────┘    │      │    └───────────────┘   │
 *    │           │            │      │            │           │
 *    │           ▼            │      │            ▼           │
 *    │   ┌───────────────┐    │      │    ┌───────────────┐   │
 *    │   │  Storage Key  │    │      │    │  Storage Key  │   │
 *    │   └───────────────┘    │      │    └───────────────┘   │
 *    │           │            │      │            │           │
 *    │           ▼            │      │            ▼           │
 *    │    ┌────────────────┐  │      │     ┌────────────────┐ │
 *    │   ┌┴───────────────┐│  │      │    ┌┴───────────────┐│ │
 *    │  ┌┴──────────────┐ ├┘  │      │   ┌┴──────────────┐ ├┘ │
 *    │  │  Child Keys   ├─┘   │      │   │  Child Keys   ├─┘  │
 *    │  └───────────────┘     │      │   └───────────────┘    │
 *    └────────────────────────┘      └────────────────────────┘
 */

use tss_esapi::{
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, EccPoint, EccScheme, KeyDerivationFunctionScheme,
        KeyedHashScheme, MaxBuffer, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa,
        PublicKeyedHashParameters, PublicRsaParametersBuilder, RsaExponent, SymmetricDefinition,
        SymmetricDefinitionObject,
    },
    // session_handles::PolicySession,
    Context,
    TctiNameConf,
};

use std::convert::{TryFrom, TryInto};

fn main() {
    // We're going to duplicate a HMAC key between two TPM's. Here is some data to HMAC
    // to prove it worked.
    let input_data = MaxBuffer::try_from("Duplicating keys is fun ...".as_bytes().to_vec())
        .expect("Failed to create buffer for input data.");

    // Create a pair of TPM's contexts - It's not "perfect" but it's what we will use
    // to represent the two TPM's in our test.
    //
    // This reads from the environment variable `TPM2TOOLS_TCTI` or `TCTI`
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager.
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

    // On both contexts, create their primary key.
    let primary_key_1 = create_primary_key(&mut context_1);
    let primary_key_2 = create_primary_key(&mut context_2);

    // TODO: Perform duplication without policy duplication select (something
    // like auth/password perhaps?). Currently with policy duplication select
    // you have to nominate the target TPM at key creation time, and I honestly
    // can't find a way to change that in future to allow more TPM's to be allowed.
    //
    // Likely it will be more flexible for people if they can authorise duplication
    // with a value like a pw.

    // Get the new_parent_name. This is needed to satisfy the policy to allow duplication.
    let (_, target_parent_name, _) = context_2
        .execute_with_nullauth_session(|ctx| ctx.read_public(primary_key_2.key_handle))
        .unwrap();

    // Now create the policy digest that will be used on TPM 1 during the creation of
    // the storage key. This will allow TPM 1 to send the key to TPM 2.

    let policy_digest = context_1
        .execute_without_session(|ctx| {
            let trial_session = ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Trial,
                    SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                )
                .expect("Start auth session failed")
                .expect("Start auth session returned a NONE handle");

            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();
            ctx.tr_sess_set_attributes(
                trial_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

            let policy_session = PolicySession::try_from(trial_session)
                .expect("Failed to convert auth session into policy session");

            ctx.policy_duplication_select(
                policy_session,
                Vec::<u8>::new().try_into().unwrap(),
                target_parent_name.clone(),
                false,
            )
            .expect("Policy duplication select");

            ctx.policy_get_digest(policy_session)
        })
        .unwrap();

    // Create the storage key on TPM-1, using the policy digest we just created.
    let object_attributes = ObjectAttributesBuilder::new()
        // For a key to be duplicated, it must have fixed TPM and parent as false.
        .with_fixed_tpm(false)
        .with_fixed_parent(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()
        .expect("Attributes to be valid");

    /*
    let storage_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                RsaKeyBits::Rsa2048,
                RsaExponent::default(),
            )
            .build()
            .expect("Params to be valid"),
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("public to be valid");
    */

    let storage_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        // Use policy digest computed using the trial session
        .with_auth_policy(policy_digest)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .unwrap(),
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .expect("storage public to be valid");

    let storage_key = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.create(
                primary_key_1.key_handle,
                storage_public,
                None,
                None,
                None,
                None,
            )
        })
        .map_err(|err| {
            // ⚠️  TSS Layer: TPM, Code: 0x000002D6, Message: Unsupported symmetric algorithm or key size, or not appropriate for instance (associated with parameter number 2).
            eprintln!("⚠️  {}", err);
            err
        })
        .unwrap();

    // Load the key.
    let loaded_storage_key = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.load(
                primary_key_1.key_handle,
                storage_key.out_private.clone(),
                storage_key.out_public.clone(),
            )
        })
        .unwrap();

    // Now we can create a child key that we will be able to move along with the parent.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()
        .expect("Failed to build object attributes");

    let hmac_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let hmac_key = context_1
        .execute_with_nullauth_session(|ctx| {
            ctx.create(loaded_storage_key, hmac_public, None, None, None, None)
        })
        .map_err(|err| {
            eprintln!("⚠️  {}", err);
            err
        })
        .unwrap();

    // Do an hmac with it.
    let hmac1 = context_1
        .execute_with_nullauth_session(|ctx| {
            let loaded_hmackey = ctx
                .load(
                    loaded_storage_key,
                    hmac_key.out_private.clone(),
                    hmac_key.out_public.clone(),
                )
                .unwrap();

            ctx.execute_with_temporary_object(loaded_hmackey.into(), |ctx, handle| {
                ctx.hmac(handle.into(), input_data.clone(), HashingAlgorithm::Sha256)
            })
        })
        .unwrap();

    // Great! Let's get to duplicating.

    // We need the name of the object we are duplicating - for us, that's the storage_key.

    let (_, object_to_duplicate_name, _) =
        context_1.read_public(loaded_storage_key.into()).unwrap();

    // Now, we can compute the real policy for the duplication.

    let policy_auth_session = context_1
        .execute_without_session(|ctx| {
            let policy_auth_session = ctx
                .start_auth_session(
                    None,
                    None,
                    None,
                    SessionType::Policy,
                    SymmetricDefinition::AES_128_CFB,
                    HashingAlgorithm::Sha256,
                )
                .expect("Start auth session failed")
                .expect("Start auth session returned a NONE handle");

            let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
                SessionAttributesBuilder::new()
                    .with_decrypt(true)
                    .with_encrypt(true)
                    .build();
            ctx.tr_sess_set_attributes(
                policy_auth_session,
                policy_auth_session_attributes,
                policy_auth_session_attributes_mask,
            )
            .expect("tr_sess_set_attributes call failed");

            let policy_session = PolicySession::try_from(policy_auth_session)
                .expect("Failed to convert auth session into policy session");

            ctx.policy_duplication_select(
                policy_session,
                object_to_duplicate_name,
                target_parent_name,
                false,
            )
            .map(|_| policy_auth_session)
        })
        .unwrap();

    // ALWAYS FAILS!!!
    // For some reason this has a policy error - I was copy pasting from the
    // tests in duplication_commands_tests.rs
    let public = storage_key.out_public.clone();
    let (data, duplicate, secret) = context_1
        .execute_with_session(Some(policy_auth_session), |ctx| {
            let new_parent_handle = ctx
                .load_external_public(primary_key_2.out_public.clone(), Hierarchy::Null)
                .unwrap();

            // TODO: Is it possible to use a non-null symdef?
            ctx.execute_with_temporary_object(new_parent_handle.into(), |ctx, new_parent_handle| {
                ctx.duplicate(
                    loaded_storage_key.into(),
                    new_parent_handle,
                    None,
                    SymmetricDefinitionObject::Null,
                )
            })
        })
        .unwrap();

    // ---------------------------------------------------------
    // Now setup to load the storage key into the second context.

    let private_storage_key_2 = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.import(
                primary_key_2.key_handle.into(),
                Some(data),
                public.clone(),
                duplicate,
                secret,
                SymmetricDefinitionObject::Null,
            )
        })
        .unwrap();

    // Now it can be loaded.

    let loaded_storage_key_2 = context_2
        .execute_with_nullauth_session(|ctx| {
            ctx.load(primary_key_2.key_handle, private_storage_key_2, public)
        })
        .unwrap();

    // And now it's descendants can be loaded and used too.

    /*
    let hmac2 = context_2
        .execute_with_nullauth_session(|ctx| {
            let loaded_hmackey = ctx.load(
                loaded_storage_key_2,
                hmac_key.out_private.clone(),
                hmac_key.out_public.clone(),
            ).unwrap();

            ctx.execute_with_temporary_object(loaded_hmackey.into(), |ctx, handle| {
                ctx.hmac(
                    handle.into(),
                    input_data.clone(),
                    HashingAlgorithm::Sha256,
                )
            })
        })
        .unwrap();

    assert_eq!(hmac1, hmac2);
    */
}

// TODO: Is there a way to add entropy or randomness here so that the created primary keys
// are not the same?
fn create_primary_key(context: &mut Context) -> CreatePrimaryKeyResult {
    context
        .execute_with_nullauth_session(|ctx| {
            let object_attributes = ObjectAttributesBuilder::new()
                // The primary keys can be fixed tpm/parent
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_decrypt(true)
                .with_sign_encrypt(false)
                .with_restricted(true)
                .build()
                .expect("Attributes to be valid");

            /*
            let public = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Rsa)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_rsa_parameters(
                    PublicRsaParametersBuilder::new_restricted_decryption_key(
                        SymmetricDefinitionObject::AES_128_CFB,
                        RsaKeyBits::Rsa2048,
                        RsaExponent::default(),
                    )
                    .build()
                    .expect("Params to be valid"),
                )
                .with_rsa_unique_identifier(PublicKeyRsa::default())
                .build()
                .expect("public to be valid");
            */

            let public = PublicBuilder::new()
                .with_public_algorithm(PublicAlgorithm::Ecc)
                .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
                .with_object_attributes(object_attributes)
                .with_ecc_parameters(
                    PublicEccParametersBuilder::new_restricted_decryption_key(
                        SymmetricDefinitionObject::AES_128_CFB,
                        EccCurve::NistP256,
                    )
                    .build()
                    .expect("Params to be valid"),
                )
                .with_ecc_unique_identifier(EccPoint::default())
                .build()
                .expect("public to be valid");

            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .unwrap()
}
