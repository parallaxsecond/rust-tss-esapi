// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::KeyHandle,
    structures::Data,
    structures::{EccPoint, PublicKeyRsa, RsaDecryptionScheme},
    tss2_esys::{Esys_ECDH_KeyGen, Esys_ECDH_ZGen, Esys_RSA_Decrypt, Esys_RSA_Encrypt},
    Context, Result, ReturnCode,
};
use log::error;
use std::ptr::null_mut;
use std::{convert::TryFrom, ptr::null};

impl Context {
    /// Perform an asymmetric RSA encryption.
    ///
    /// # Arguments
    ///
    /// * `key_handle` - A [KeyHandle] to to public portion of RSA key to use for encryption.
    /// * `message`    - The message to be encrypted.
    /// * `in_scheme`  - The padding scheme to use if scheme associated with
    ///   the `key_handle` is [RsaDecryptionScheme::Null].
    /// * `label`      - An optional label to be associated with the message.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command performs RSA encryption using the indicated padding scheme
    /// > according to IETF [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017).
    ///
    /// > The label parameter is optional. If provided (label.size != 0) then the TPM shall return TPM_RC_VALUE if
    /// > the last octet in label is not zero. The terminating octet of zero is included in the label used in the padding
    /// > scheme.
    /// > If the scheme does not use a label, the TPM will still verify that label is properly formatted if label is
    /// > present.
    ///
    /// # Returns
    ///
    /// The encrypted output.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, RsaScheme, PublicBuilder, PublicRsaParametersBuilder, PublicKeyRsa,
    /// #       RsaDecryptionScheme, HashScheme, SymmetricDefinition, RsaExponent,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # #[serial_test::file_serial]
    /// # fn main() {
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::getrandom(&mut random_digest).unwrap();
    /// # let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();
    /// #
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(false)
    /// #     .build()
    /// #     .expect("Should be able to build object attributes when the attributes are not conflicting.");
    /// #
    /// # let key_pub = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new()
    /// #             .with_scheme(RsaScheme::Null)
    /// #             .with_key_bits(RsaKeyBits::Rsa2048)
    /// #             .with_exponent(RsaExponent::default())
    /// #             .with_is_signing_key(true)
    /// #             .with_is_decryption_key(true)
    /// #             .with_restricted(false)
    /// #             .build()
    /// #             .expect("Should be possible to build valid RSA parameters")
    /// #    )
    /// #    .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #    .build()
    /// #    .expect("Should be possible to build a valid Public object.");
    /// #
    /// # let key_handle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         key_pub,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .expect("Should be possible to create primary key from using valid Public object.")
    /// #     .key_handle;
    /// // Because the key was created with RsaScheme::Null it is possible to
    /// // provide a scheme for the rsa_encrypt function to use.
    /// let scheme =
    ///        RsaDecryptionScheme::create(RsaDecryptAlgorithm::Oaep, Some(HashingAlgorithm::Sha256))
    ///            .expect("Failed to create rsa decryption scheme");
    /// let plain_text_bytes = vec![1, 2, 3, 4];
    /// let message_in = PublicKeyRsa::try_from(plain_text_bytes.clone())
    ///     .expect("Should be possible to create a PublicKeyRsa object from valid bytes.");
    /// let cipher_text = context.rsa_encrypt(key_handle, message_in, scheme, None)
    ///     .expect("Should be possible to call rsa_encrypt using valid arguments.");
    /// # let message_out = context.rsa_decrypt(key_handle, cipher_text, scheme, None)
    /// #     .expect("Should be possible to call rsa_decrypt using valid arguments.");
    /// # let decrypted_bytes = message_out.as_bytes();
    /// # assert_eq!(plain_text_bytes, decrypted_bytes);
    /// # }
    /// ```
    pub fn rsa_encrypt(
        &mut self,
        key_handle: KeyHandle,
        message: PublicKeyRsa,
        in_scheme: RsaDecryptionScheme,
        label: impl Into<Option<Data>>,
    ) -> Result<PublicKeyRsa> {
        let mut out_data_ptr = null_mut();
        let potential_label = label.into().map(|v| v.into());
        let label_ptr = potential_label
            .as_ref()
            .map_or_else(null, std::ptr::from_ref);
        ReturnCode::ensure_success(
            unsafe {
                Esys_RSA_Encrypt(
                    self.mut_context(),
                    key_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &message.into(),
                    &in_scheme.into(),
                    label_ptr,
                    &mut out_data_ptr,
                )
            },
            |ret| {
                error!("Error when performing RSA encryption: {:#010X}", ret);
            },
        )?;
        PublicKeyRsa::try_from(Context::ffi_data_to_owned(out_data_ptr)?)
    }

    /// Perform an asymmetric RSA decryption.
    ///
    /// # Arguments
    ///
    /// * `key_handle`  - A [KeyHandle] of the RSA key to use for decryption.
    /// * `cipher_text` - The cipher text to be decrypted.
    /// * `in_scheme`  - The padding scheme to use if scheme associated with
    ///   the `key_handle` is [RsaDecryptionScheme::Null].
    /// * `label`       - An optional label whose association with the message is to be verified.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command performs RSA decryption using the indicated padding scheme according to IETF RFC
    /// > 8017 ((PKCS#1).
    ///
    /// > If a label is used in the padding process of the scheme during encryption, the label parameter is required
    /// > to be present in the decryption process and label is required to be the same in both cases. If label is not
    /// > the same, the decrypt operation is very likely to fail.
    ///
    /// # Returns
    ///
    /// The decrypted output.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, RsaScheme, PublicBuilder, PublicRsaParametersBuilder, PublicKeyRsa,
    /// #       RsaDecryptionScheme, HashScheme, SymmetricDefinition, RsaExponent,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::getrandom(&mut random_digest).unwrap();
    /// # let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();
    /// #
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(false)
    /// #     .build()
    /// #     .expect("Should be able to build object attributes when the attributes are not conflicting.");
    /// #
    /// # let key_pub = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new()
    /// #             .with_scheme(RsaScheme::Null)
    /// #             .with_key_bits(RsaKeyBits::Rsa2048)
    /// #             .with_exponent(RsaExponent::default())
    /// #             .with_is_signing_key(true)
    /// #             .with_is_decryption_key(true)
    /// #             .with_restricted(false)
    /// #             .build()
    /// #             .expect("Should be possible to build valid RSA parameters")
    /// #    )
    /// #    .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #    .build()
    /// #    .expect("Should be possible to build a valid Public object.");
    /// #
    /// # let key_handle = context
    /// #     .create_primary(
    /// #         Hierarchy::Owner,
    /// #         key_pub,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         None,
    /// #     )
    /// #     .expect("Should be possible to create primary key from using valid Public object.")
    /// #     .key_handle;
    /// # let scheme =
    /// #        RsaDecryptionScheme::create(RsaDecryptAlgorithm::RsaEs, None)
    /// #            .expect("Failed to create rsa decryption scheme");
    /// # let plain_text_bytes = vec![4, 3, 2, 1, 0];
    /// # let message_in = PublicKeyRsa::try_from(plain_text_bytes.clone())
    /// #     .expect("Should be possible to create a PublicKeyRsa object from valid bytes.");
    /// # let label = Data::default();
    /// # let cipher_text = context.rsa_encrypt(key_handle, message_in, scheme, label.clone())
    /// #     .expect("Should be possible to call rsa_encrypt using valid arguments.");
    /// // label text needs to be the same as the on used when data was encrypted.
    /// let message_out = context.rsa_decrypt(key_handle, cipher_text, scheme, label)
    ///     .expect("Should be possible to call rsa_decrypt using valid arguments.");
    /// let decrypted_bytes = message_out.as_bytes();
    /// # assert_eq!(plain_text_bytes, decrypted_bytes);
    /// ```
    pub fn rsa_decrypt(
        &mut self,
        key_handle: KeyHandle,
        cipher_text: PublicKeyRsa,
        in_scheme: RsaDecryptionScheme,
        label: impl Into<Option<Data>>,
    ) -> Result<PublicKeyRsa> {
        let mut message_ptr = null_mut();
        let potential_label = label.into().map(|v| v.into());
        let label_ptr = potential_label
            .as_ref()
            .map_or_else(null, std::ptr::from_ref);
        ReturnCode::ensure_success(
            unsafe {
                Esys_RSA_Decrypt(
                    self.mut_context(),
                    key_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &cipher_text.into(),
                    &in_scheme.into(),
                    label_ptr,
                    &mut message_ptr,
                )
            },
            |ret| {
                error!("Error when performing RSA decryption: {:#010X}", ret);
            },
        )?;
        PublicKeyRsa::try_from(Context::ffi_data_to_owned(message_ptr)?)
    }

    /// Generate an ephemeral key pair.
    ///
    /// # Arguments
    /// * `key_handle`- A [KeyHandle] of ECC key which curve parameters will be used
    ///   to generate the ephemeral key.
    ///
    /// # Details
    /// This command uses the TPM to generate an ephemeral
    /// key pair. It uses the private ephemeral key and a loaded
    /// public key to compute the shared secret value.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        ecc::EccCurve,
    /// #        reserved_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, EccScheme, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, KeyDerivationFunctionScheme, EccPoint,
    /// #        RsaDecryptionScheme, HashScheme, SymmetricDefinition,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # #[serial_test::file_serial]
    /// # fn main() {
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::getrandom(&mut random_digest).unwrap();
    /// # let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();
    /// #
    /// // Create a key suitable for ECDH key generation
    /// let ecc_parms = PublicEccParametersBuilder::new()
    ///     .with_ecc_scheme(
    ///         EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)),
    ///     )
    ///     .with_curve(EccCurve::NistP256)
    ///     .with_is_signing_key(false)
    ///     .with_is_decryption_key(true)
    ///     .with_restricted(false)
    ///     .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
    ///     .build()
    ///     .unwrap();
    ///
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_fixed_tpm(true)
    ///     .with_fixed_parent(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .with_decrypt(true)
    ///     .with_sign_encrypt(false)
    ///     .with_restricted(false)
    ///     .build()
    ///     .unwrap();
    ///
    /// let public = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::Ecc)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_ecc_parameters(ecc_parms)
    ///     .with_ecc_unique_identifier(EccPoint::default())
    ///     .build()
    ///     .unwrap();
    ///
    /// let key_handle = context
    ///     .create_primary(
    ///         Hierarchy::Owner,
    ///         public,
    ///         Some(key_auth),
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .unwrap()
    ///     .key_handle;
    ///
    /// // Generate ephemeral key pair and a shared secret
    /// let (z_point, pub_point) = context.ecdh_key_gen(key_handle).unwrap();
    /// # }
    /// ```
    pub fn ecdh_key_gen(&mut self, key_handle: KeyHandle) -> Result<(EccPoint, EccPoint)> {
        let mut z_point_ptr = null_mut();
        let mut pub_point_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ECDH_KeyGen(
                    self.mut_context(),
                    key_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut z_point_ptr,
                    &mut pub_point_ptr,
                )
            },
            |ret| {
                error!("Error when generating ECDH key pair: {:#010X}", ret);
            },
        )?;

        let z_point = Context::ffi_data_to_owned(z_point_ptr)?;
        let pub_point = Context::ffi_data_to_owned(pub_point_ptr)?;
        Ok((
            EccPoint::try_from(z_point.point)?,
            EccPoint::try_from(pub_point.point)?,
        ))
    }

    /// Recover Z value from a public point and a private key.
    ///
    /// # Arguments
    /// * `key_handle` - A [KeyHandle] of ECC key which curve parameters will be used
    ///   to generate the ephemeral key.
    /// * `in_point` - An [EccPoint] on the curve of the key referenced by `key_handle`
    ///
    /// # Details
    /// This command uses the TPM to recover the Z value from a public point and a private key.
    /// It will perform the multiplication of the provided `in_point` with the private key and
    /// return the coordinates of the resultant point.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{
    /// #            HashingAlgorithm, PublicAlgorithm, RsaDecryptAlgorithm,
    /// #        },
    /// #        ecc::EccCurve,
    /// #        reserved_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, Data, EccScheme, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, KeyDerivationFunctionScheme, EccPoint,
    /// #        RsaDecryptionScheme, HashScheme, SymmetricDefinition,
    /// #    },
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # #[serial_test::file_serial]
    /// # fn main() {
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::getrandom(&mut random_digest).unwrap();
    /// # let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();
    /// #
    /// // Create a key suitable for ECDH key generation
    /// let ecc_parms = PublicEccParametersBuilder::new()
    ///     .with_ecc_scheme(
    ///         EccScheme::EcDh(HashScheme::new(HashingAlgorithm::Sha256)),
    ///     )
    ///     .with_curve(EccCurve::NistP256)
    ///     .with_is_signing_key(false)
    ///     .with_is_decryption_key(true)
    ///     .with_restricted(false)
    ///     .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
    ///     .build()
    ///     .unwrap();
    ///
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_fixed_tpm(true)
    ///     .with_fixed_parent(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .with_decrypt(true)
    ///     .with_sign_encrypt(false)
    ///     .with_restricted(false)
    ///     .build()
    ///     .unwrap();
    ///
    /// let public = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::Ecc)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_ecc_parameters(ecc_parms)
    ///     .with_ecc_unique_identifier(EccPoint::default())
    ///     .build()
    ///     .unwrap();
    ///
    /// let key_handle = context
    ///     .create_primary(
    ///         Hierarchy::Owner,
    ///         public,
    ///         Some(key_auth),
    ///         None,
    ///         None,
    ///         None,
    ///     )
    ///     .unwrap()
    ///     .key_handle;
    ///
    /// // Generate ephemeral key pair and a shared secret
    /// let (z_point, pub_point) = context.ecdh_key_gen(key_handle).unwrap();
    /// let z_point_gen = context.ecdh_z_gen(key_handle, pub_point).unwrap();
    /// assert_eq!(z_point.x().as_bytes(), z_point_gen.x().as_bytes());
    /// # }
    /// ```
    pub fn ecdh_z_gen(&mut self, key_handle: KeyHandle, in_point: EccPoint) -> Result<EccPoint> {
        let mut out_point_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ECDH_ZGen(
                    self.mut_context(),
                    key_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &in_point.into(),
                    &mut out_point_ptr,
                )
            },
            |ret| {
                error!("Error when performing ECDH ZGen: {:#010X}", ret);
            },
        )?;
        let out_point = Context::ffi_data_to_owned(out_point_ptr)?;
        EccPoint::try_from(out_point.point)
    }

    // Missing function: ECC_Parameters
    // Missing function: ZGen_2Phase
}
