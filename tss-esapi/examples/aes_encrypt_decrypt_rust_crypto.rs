// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/*
 * This example demonstrates how to use AES for symmetric encryption and decryption
 */

use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    handles::KeyHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        key_bits::AesKeyBits,
        reserved_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, InitialValue, MaxBuffer, PublicBuilder,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    Context, TctiNameConf,
};

use cipher::BlockEncryptMut;

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
    // content encryption key (CEK), which can be decrypted and released and then used to decrypt
    // the actual data in question outside of the TPM.
    //
    // TPMs also tend to be "slower" for encryption/decryption, so you should consider the
    // CEK pattern for performance reasons.
    let data_to_encrypt = "TPMs are super cool, you should use them! They are even better when you can use other interfaces like Rust Crypto!"
        .as_bytes()
        .to_vec();

    eprintln!("{:?}", data_to_encrypt.len());
    eprintln!("{:?}", data_to_encrypt);
    eprintln!("--");

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

    let encrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            let aes_key = ctx
                .load(primary.key_handle, enc_private.clone(), public.clone())
                .unwrap();

            let aes_128_cbc_enc = TpmAes128CbcEnc {
                cipher: TpmEnc {
                    ctx,
                    handle: aes_key,
                    iv: initial_value.clone(),
                },
            };

            let enc_data = aes_128_cbc_enc
                .encrypt_padded_vec_mut::<cipher::block_padding::Pkcs7>(&data_to_encrypt);

            Ok::<_, tss_esapi::Error>(enc_data)
        })
        .unwrap();

    /*
    // Since AES is symmetric, we need the private component of the key to encrypt or decrypt
    // any values.
    let (encrypted_data, _initial_value) =
    context
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

    assert_ne!(encrypted_data.as_slice(), padded_data_to_encrypt.as_slice());

    */

    let encrypted_data = MaxBuffer::try_from(encrypted_data).unwrap();

    // The data is now encrypted.
    println!("encrypted_data = {:?}", encrypted_data);

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

    const AES_BLOCK_SIZE: usize = 16;

    // WARNING: Manually implemented pkcs7 follows. This has not been audited. Don't use this
    // in production.

    let last_byte = decrypted_data.len() - 1;
    let k_byte = decrypted_data[last_byte];
    // Since pkcs7 padding repeats this byte k times, we check that this byte
    // is repeated as many times as expected. In theory we don't need this check
    // but it's better to be defensive.

    eprintln!("{:?}", decrypted_data);

    if k_byte as usize > AES_BLOCK_SIZE {
        eprintln!("{}", k_byte);
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

    // END WARNING

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

// In the future I would probably do this where the object is actually a
// stored context that is loaded/unloaded as required. We would also check
// the handle is suitable for this purpose etc.
struct TpmAes128CbcEnc<'a> {
    cipher: TpmEnc<'a>,
}

struct TpmEnc<'a> {
    ctx: &'a mut Context,
    handle: KeyHandle,
    iv: InitialValue,
}

impl<'a> cipher::BlockSizeUser for TpmAes128CbcEnc<'a> {
    type BlockSize = cipher::consts::U16;
}

impl<'a> cipher::BlockEncryptMut for TpmAes128CbcEnc<'a> {
    fn encrypt_with_backend_mut(
        &mut self,
        f: impl cipher::BlockClosure<BlockSize = Self::BlockSize>,
    ) {
        // No errors? I'll raise an issue.
        let Self { cipher } = self;

        f.call(cipher)
    }
}

impl<'a> cipher::BlockSizeUser for TpmEnc<'a> {
    type BlockSize = cipher::consts::U16;
}

impl<'a> cipher::ParBlocksSizeUser for TpmEnc<'a> {
    // 1024 / 16 bytes
    type ParBlocksSize = cipher::consts::U16;
}

impl<'a> cipher::BlockBackend for TpmEnc<'a> {
    fn proc_block(&mut self, mut block: cipher::inout::InOut<'_, '_, cipher::Block<Self>>) {
        // TODO: Do we need to mutate current iv as we go?
        let decrypt = false;

        let data_in = MaxBuffer::try_from(block.clone_in().to_vec()).unwrap();

        eprintln!("data_in: {:?}", data_in);

        let (encrypted_data, initial_value) = self
            .ctx
            .encrypt_decrypt_2(
                self.handle,
                decrypt,
                SymmetricMode::Cbc,
                data_in,
                self.iv.clone(),
            )
            .unwrap();

        self.iv = initial_value;

        eprintln!("encrypted: {:?}", encrypted_data);

        block.get_out().copy_from_slice(encrypted_data.as_slice());
    }
}
