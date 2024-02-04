// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to use AES for symmetric encryption and decryption
 */

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        key_bits::AesKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, InitialValue, MaxBuffer, PublicBuilder,
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

    // Begin to create our new AES symmetric key

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(true)
        // Note that we don't set the key as restricted.
        .build()
        .expect("Failed to build object attributes");

    let aes_params = SymmetricCipherParameters::new(SymmetricDefinitionObject::Aes {
        key_bits: AesKeyBits::Aes128,
        mode: SymmetricMode::Cbc,
    });

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(aes_params)
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let (enc_private, public) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))
        })
        .unwrap();

    // The data we wish to encrypt. Be aware that there is a limit to the size of this data
    // that can be encrypted or decrypted (1024 bytes). In some cases you may need to encrypt a
    // "content encryption key", which can be decrypted and released and then used to decrypt
    // the actual data in question outside of the TPM.
    //
    // TPMs also tend to be "slower" for encryption/decryption, so you may consider the
    // CEK pattern for performance reasons.
    let data_to_encrypt = "TPMs are super cool, you should use them!"
        .as_bytes()
        .to_vec();

    eprintln!("{:?}", data_to_encrypt.len());

    // Input data needs to always be a multiple of AES_BLOCK_SIZE, so we implement PKCS7 padding
    // to achieve this.

    // REVIEW NOTE: Tss-esapi likely should expose these as constants from AesKeyBits::Aes128
    // to prevent ambiguity!
    const AES_BLOCK_SIZE: usize = 16;

    // REVIEW NOTE: Should we added PKCS7 padding as a function to MaxBuffer to prevent
    // people needing to "roll their own"?

    let need_k_bytes = AES_BLOCK_SIZE - (data_to_encrypt.len() % AES_BLOCK_SIZE);
    // PKCS7 always pads to remove ambiguous situations.
    let need_k_bytes = if need_k_bytes == 0 {
        AES_BLOCK_SIZE
    } else {
        need_k_bytes
    };

    let new_len = data_to_encrypt.len() + need_k_bytes;

    let mut padded_data_to_encrypt = data_to_encrypt.to_vec();
    padded_data_to_encrypt.resize(new_len, need_k_bytes as u8);

    let padded_data_to_encrypt = MaxBuffer::try_from(padded_data_to_encrypt).unwrap();

    // Padding always has to be added.
    assert_ne!(
        data_to_encrypt.as_slice(),
        padded_data_to_encrypt.as_slice()
    );

    // AES requires a random initial_value before any encryption or decryption. This must
    // be persisted with the encrypted data, else decryption can not be performed.
    // This value MUST be random, and should never be reused between different encryption
    // operations.
    let initial_value = context
        .execute_with_nullauth_session(|ctx| {
            ctx.get_random(InitialValue::MAX_SIZE)
                .and_then(|random| InitialValue::try_from(random.to_vec()))
        })
        .unwrap();

    // Since AES is symmetric, we need the private component of the key to encrypt or decrypt
    // any values.
    let (encrypted_data, _initial_value) = context
        .execute_with_nullauth_session(|ctx| {
            let aes_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();

            let decrypt = false;

            ctx.encrypt_decrypt_2(
                aes_key,
                decrypt,
                SymmetricMode::Cbc,
                padded_data_to_encrypt.clone(),
                initial_value.clone(),
            )
        })
        .unwrap();

    // The data is now encrypted.
    println!("encrypted_data = {:?}", encrypted_data);
    assert_ne!(encrypted_data.as_slice(), padded_data_to_encrypt.as_slice());

    // Decryption is the identical process with the "decrypt" flag set to true.
    let (decrypted_data, _initial_value) = context
        .execute_with_nullauth_session(|ctx| {
            let aes_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();

            let decrypt = true;

            ctx.encrypt_decrypt_2(
                aes_key,
                decrypt,
                SymmetricMode::Cbc,
                encrypted_data.clone(),
                initial_value,
            )
        })
        .unwrap();

    // Now we have to un-pad the output.
    if decrypted_data.is_empty() {
        panic!("Should not be empty");
    }

    let last_byte = decrypted_data.len() - 1;
    let k_byte = decrypted_data[last_byte];
    // Since pkcs7 padding repeats this byte k times, we check that this byte
    // is repeated as many times as expected. In theory we don't need this check
    // but it's better to be defensive.

    if k_byte as usize > AES_BLOCK_SIZE {
        panic!("Invalid pad byte, exceeds AES_BLOCK_SIZE");
    }

    for i in 0..k_byte {
        if decrypted_data[last_byte - i as usize] != k_byte {
            panic!("Invalid pad byte, is not equal to k_byte");
        }
    }

    let truncate_to = decrypted_data.len().checked_sub(k_byte as usize).unwrap();
    let mut decrypted_data = decrypted_data.to_vec();
    decrypted_data.truncate(truncate_to);

    println!("data_to_encrypt = {:?}", data_to_encrypt);
    println!("decrypted_data = {:?}", decrypted_data);
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
