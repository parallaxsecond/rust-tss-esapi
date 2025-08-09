// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to use RSA OAEP for encryption and decryption
 */

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        key_bits::RsaKeyBits,
        reserved_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Data, Digest, HashScheme, PublicBuilder, PublicKeyRsa,
        PublicRsaParametersBuilder, RsaDecryptionScheme, RsaExponent, RsaScheme,
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

    // This example won't go over the process to create a new parent. For more detail see `examples/hmac.rs`.

    let primary = create_primary(&mut context);

    // Begin to create our new RSA key.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // We need a key that can decrypt values - we don't need to worry
        // about signatures.
        .with_decrypt(true)
        // Note that we don't set the key as restricted.
        .build()
        .expect("Failed to build object attributes");

    let rsa_params = PublicRsaParametersBuilder::new()
        // The value for scheme may have requirements set by a combination of the
        // sign, decrypt, and restricted flags. For an unrestricted signing and
        // decryption key then scheme must be NULL. For an unrestricted decryption key,
        // NULL, OAEP or RSAES are valid for use.
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_decryption_key(true)
        // We don't require signatures, but some users may.
        // .with_is_signing_key(true)
        .with_restricted(false)
        .build()
        .expect("Failed to build rsa parameters");

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .unwrap();

    let (enc_private, public) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))
        })
        .unwrap();

    let data_to_encrypt = PublicKeyRsa::try_from("TPMs are cool.".as_bytes().to_vec())
        .expect("Failed to create buffer for data to encrypt.");

    // To encrypt data to a key, we only need it's public component. We demonstrate how
    // to load that public component into a TPM and then encrypt to it.
    let encrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            let rsa_pub_key = ctx
                .load_external_public(public.clone(), Hierarchy::Null)
                .unwrap();

            ctx.rsa_encrypt(
                rsa_pub_key,
                data_to_encrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .unwrap();

    // The data is now encrypted.
    println!("encrypted_data = {encrypted_data:?}");
    assert_ne!(encrypted_data, data_to_encrypt);

    // To decrypt the data, we need to load the private key into the TPM.
    let decrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            let rsa_priv_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();

            ctx.rsa_decrypt(
                rsa_priv_key,
                encrypted_data,
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .unwrap();

    println!("data_to_encrypt = {data_to_encrypt:?}");
    println!("decrypted_data = {decrypted_data:?}");
    // They are the same!
    assert_eq!(data_to_encrypt, decrypted_data);
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
