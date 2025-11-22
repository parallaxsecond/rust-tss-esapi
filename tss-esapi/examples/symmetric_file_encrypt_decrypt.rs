use core::str;
use std::{convert::TryFrom, fs, path::Path};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm, SymmetricMode},
        reserved_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, InitialValue, MaxBuffer, PublicBuilder,
        SymmetricCipherParameters, SymmetricDefinitionObject,
    },
    Context, TctiNameConf,
};

const DEFAULT_INITIAL_DATA_FILE: &str =
    "tss-esapi/examples/symmetric_file_encrypt_decrypt_example.txt";

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

    // Create the AES key. This key exists under the primary key in it's hierarchy
    // and can only be used if the same primary key is recreated from the parameters
    // defined above.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(true)
        .build()
        .expect("Failed to build object attributes");

    let key_pub = PublicBuilder::new()
        // This key is an AES key
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .unwrap();

    let (private, public) = context
        .execute_with_nullauth_session(|ctx| {
            // Create the AES key given our primary key as it's parent. This returns the private
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
    // The enc_private and public values can be serialized and persisted - that way they can
    // be reloaded for future use.

    // We load the data from a file system file, it can be somewhat large (like a certificate), larger than MaxBuffer::MAX_SIZE
    let initial_data_file_str = std::env::var("EXAMPLES_INITIAL_DATA_FILE")
        .unwrap_or(DEFAULT_INITIAL_DATA_FILE.to_string());
    let initial_data_file = Path::new(&initial_data_file_str);
    if !initial_data_file.is_file() {
        panic!(
            "The initial data file: {}, does not exist",
            initial_data_file.display()
        );
    }
    let initial_data = fs::read(initial_data_file).expect("could not open data file");

    // We create an initialisation vector, since it is needed for decryption, it should be persisted in a real world use case
    let iv = context
        .execute_with_nullauth_session(|ctx| {
            InitialValue::from_bytes(
                ctx.get_random(16)
                    .expect("could not get random bytes for initialisation vector")
                    .as_bytes(),
            )
        })
        .expect("could not create iv from random bytes");

    // We encrypt the data
    let encrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            let mut encrypted_data = Vec::new();
            let handle = ctx
                .load(primary.key_handle, private.clone(), public.clone())
                .expect("could not load child key");

            let mut chunk_iv = iv.clone();

            // This file is larger than the MaxBuffer::MAX_SIZE, so we need to chunk it
            // The iv must be different for every chunk, the encrypt_decrypt_2 function conveniently provide a new one at each iteration
            for chunk in initial_data.chunks(MaxBuffer::MAX_SIZE) {
                let data = MaxBuffer::try_from(Vec::from(chunk))
                    .expect("failed to create data from file buffer chunk");
                let (enc_data, chunk_iv_out) = ctx.encrypt_decrypt_2(
                    handle,             // Handle to a symmetric key
                    false,              // false, indicates that the data should be encrypted
                    SymmetricMode::Cfb, // The symmetric mode of the encryption
                    data,               // The data that is to be encrypted
                    chunk_iv,           // Initial value needed by the algorithm
                )?;
                chunk_iv = chunk_iv_out;
                encrypted_data.push(enc_data);
            }
            Ok::<Vec<MaxBuffer>, tss_esapi::Error>(encrypted_data)
        })
        .expect("Call to encrypt_decrypt_2 failed when encrypting data");
    let encrypted_data = encrypted_data
        .iter()
        .map(|e| e.as_bytes())
        .collect::<Vec<_>>()
        .concat();

    // Decrypting is exactly the opposite, with the same first iv
    let decrypted_data = context
        .execute_with_nullauth_session(|ctx| {
            let mut decrypted_data = Vec::new();
            let handle = ctx
                .load(primary.key_handle, private.clone(), public.clone())
                .expect("could not load child key");

            let mut chunk_iv = iv;

            for chunk in encrypted_data.chunks(MaxBuffer::MAX_SIZE) {
                let data = MaxBuffer::try_from(Vec::from(chunk))
                    .expect("failed to create data from encrypted data chunk");
                let (enc_data, chunk_iv_out) = ctx.encrypt_decrypt_2(
                    handle,             // Handle to a symmetric key
                    true,               // true, indicates that the data should be decrypted
                    SymmetricMode::Cfb, // The symmetric mode of the encryption
                    data,               // The data that is to be encrypted
                    chunk_iv,           // Initial value needed by the algorithm
                )?;
                chunk_iv = chunk_iv_out;
                decrypted_data.push(enc_data);
            } //
            Ok::<Vec<MaxBuffer>, tss_esapi::Error>(decrypted_data)
        })
        .expect("Call to encrypt_decrypt_2 failed when encrypting data");
    let decrypted_data = decrypted_data
        .iter()
        .map(|e| e.as_bytes())
        .collect::<Vec<_>>()
        .concat();

    println!(
        "=== Initial data ===\n\n{}\n\n\n\n",
        str::from_utf8(&initial_data).unwrap()
    );
    print!("");
    println!(
        "=== Decrypted data ===\n\n{}",
        str::from_utf8(&decrypted_data).unwrap()
    );
    // They are the same!
    assert_eq!(initial_data, decrypted_data);
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
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

    context
        .execute_with_nullauth_session(|ctx| {
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .unwrap()
}
