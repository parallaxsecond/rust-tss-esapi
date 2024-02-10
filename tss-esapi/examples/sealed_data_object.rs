// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to create a sealed data object. A sealed data object allows
 * a small amount of data to be encrypted (sealed) by the tpm. To decrypt (unseal) the object
 * requires the parent of the object to be loaded, and other policies in the TPM to be met such
 * as PCR state or a valid authValue.
 */

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, KeyedHashScheme, PublicBuilder, PublicKeyedHashParameters,
        SensitiveData, SymmetricCipherParameters, SymmetricDefinitionObject,
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

    // This example won't go over the process to create a new parent. For more detail see `examples/hmac.rs`.

    let primary = create_primary(&mut context);

    // Sensitive data is the value we want to seal. It's maximum size is determined by
    // SensitiveData::MAX_SIZE. If the data you wish to seal is larger than this size you may
    // want to seal a symmetric key that encrypts the data instead.
    let sensitive_data = SensitiveData::try_from(vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ])
    .unwrap();

    // A sealed data object is a specialised form of a HMAC key. There are strict requirements for
    // the object attributes and algorithms to signal to the TPM that this is a sealed data object.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(true)
        // To access the sealed data we require user auth or policy. In this example we
        // set a null authValue.
        .with_user_with_auth(true)
        // Must be clear (not set). This is because the sensitive data is
        // input from an external source.
        // .with_sensitive_data_origin(true)
        // For sealed data, none of sign, decrypt or restricted can be set. This indicates
        // the created object is a sealed data object.
        // .with_decrypt(false)
        // .with_restricted(false)
        // .with_sign_encrypt(false)
        .build()
        .expect("Failed to build object attributes");

    let key_pub = PublicBuilder::new()
        // A sealed data object is an HMAC key with a NULL hash scheme.
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let (enc_private, public) = context
        .execute_with_nullauth_session(|ctx| {
            // Create the sealed data object. The encrypted private component is now encrypted and
            // contains our data. Like any other TPM object, to load this we require the public
            // component as well. Both should be persisted for future use.
            ctx.create(
                primary.key_handle,
                key_pub,
                None,
                Some(sensitive_data.clone()),
                None,
                None,
            )
            .map(|key| (key.out_private, key.out_public))
        })
        .unwrap();

    let unsealed = context
        .execute_with_nullauth_session(|ctx| {
            // When we wish to unseal the data, we must load this object like any other meeting
            // any policy or authValue requirements.
            let sealed_data_object = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();

            ctx.unseal(sealed_data_object.into())
        })
        .unwrap();

    // We can now assert that we correctly unsealed our data.
    println!("sensitive_data = {:?}", sensitive_data);
    println!("unsealed_data  = {:?}", unsealed);
    assert_eq!(unsealed, sensitive_data);
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
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

    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap()
}
