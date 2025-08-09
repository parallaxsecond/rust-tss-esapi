// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to create an HMAC key that can be reloaded.
 */

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        reserved_handles::Hierarchy,
    },
    structures::{
        Digest, KeyedHashScheme, MaxBuffer, PublicBuilder, PublicKeyedHashParameters,
        SymmetricCipherParameters, SymmetricDefinitionObject,
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

    // Create the primary key. A primary key is the "root" of a collection of objects.
    // These other objects are encrypted by the primary key allowing them to persist
    // over a reboot and reloads.
    //
    // A primary key is derived from a seed, and provided that the same inputs are given
    // the same primary key will be derived in the tpm. This means that you do not need
    // to store or save the details of this key - only the parameters of how it was created.

    let object_attributes = ObjectAttributesBuilder::new()
        // Indicate the key can only exist within this tpm and can not be exported.
        .with_fixed_tpm(true)
        // The primary key and it's descendent keys can't be moved to other primary
        // keys.
        .with_fixed_parent(true)
        // The primary key will persist over suspend and resume of the system.
        .with_st_clear(false)
        // The primary key was generated entirely inside the TPM - only this TPM
        // knows it's content.
        .with_sensitive_data_origin(true)
        // This key requires "authentication" to the TPM to access - this can be
        // an HMAC or password session. HMAC sessions are used by default with
        // the "execute_with_nullauth_session" function.
        .with_user_with_auth(true)
        // This key has the ability to decrypt
        .with_decrypt(true)
        // This key may only be used to encrypt or sign objects that are within
        // the TPM - it can not encrypt or sign external data.
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        // This key is a symmetric key.
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
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap();

    // Create the HMAC key. This key exists under the primary key in it's hierarchy
    // and can only be used if the same primary key is recreated from the parameters
    // defined above.

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

    let key_pub = PublicBuilder::new()
        // This key is a HMAC key
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
            KeyedHashScheme::HMAC_SHA_256,
        ))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let (enc_private, public) = context
        .execute_with_nullauth_session(|ctx| {
            // Create the HMAC key given our primary key as it's parent. This returns the private
            // and public portions of the key. It's *important* to note that the private component
            // is *encrypted* by a key associated with the primary key. It is not plaintext or
            // leaked in this step.
            ctx.create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))
        })
        .unwrap();

    // Once the key is created, we have it's parameters in the private and public values.
    // We now need to load it into the tpm so that it can be used.
    //
    // The enc_private and public values can be serialised and persisted - that way they can
    // be reloaded for future use.

    let input_data = MaxBuffer::try_from("TPMs are cool.".as_bytes().to_vec())
        .expect("Failed to create buffer for input data.");

    let hmac1 = context
        .execute_with_nullauth_session(|ctx| {
            // Load the HMAC key into the tpm context.
            let hmac_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();
            // Perform the HMAC.
            let r = ctx.hmac(
                hmac_key.into(),
                input_data.clone(),
                HashingAlgorithm::Sha256,
            );
            // Unload the key from the context.
            ctx.flush_context(hmac_key.into()).unwrap();
            r
        })
        .unwrap();

    // Reload the key and perform the same hmac.
    let hmac2 = context
        .execute_with_nullauth_session(|ctx| {
            let hmac_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();
            let r = ctx.hmac(
                hmac_key.into(),
                input_data.clone(),
                HashingAlgorithm::Sha256,
            );
            ctx.flush_context(hmac_key.into()).unwrap();
            r
        })
        .unwrap();

    println!("hmac1 = {hmac1:?}");
    println!("hmac2 = {hmac2:?}");
    // They are the same!
    assert_eq!(hmac1, hmac2);
}
