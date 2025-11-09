// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod create_command_input;
mod create_command_output;

use crate::{
    context::handle_manager::HandleDropAction,
    handles::{KeyHandle, ObjectHandle, TpmHandle},
    interface_types::reserved_handles::Hierarchy,
    structures::{
        Auth, CreateKeyResult, Data, Digest, EncryptedSecret, IdObject, Name, PcrSelectionList,
        Private, Public, Sensitive, SensitiveData,
    },
    tss2_esys::{
        Esys_ActivateCredential, Esys_Create, Esys_Load, Esys_LoadExternal, Esys_MakeCredential,
        Esys_ObjectChangeAuth, Esys_ReadPublic, Esys_Unseal,
    },
    Context, Error, Result, ReturnCode, WrapperErrorKind,
};
use create_command_input::CreateCommandInputHandler;
use create_command_output::CreateCommandOutputHandler;
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::{null, null_mut};

impl Context {
    /// Create a key and return the handle.
    ///
    /// The authentication value, initial data, outside info and creation PCRs are passed as slices
    /// which are then converted by the method into TSS native structures.
    ///
    /// # Parameters
    /// * `parent_handle` - The [KeyHandle] of the parent for the new object that is being created.
    /// * `public` -  The public part of the object that is being created.
    /// * `auth_value` - The value used to be used for authorize usage of the object.
    /// * `sensitive_data` - The data that is to be sealed, a key or derivation values.
    /// * `outside_info` - Data that will be included in the creation data for this
    ///   object to provide permanent, verifiable linkage between the object
    ///   that is being created and some object owner data.
    /// * `creation_pcrs`- PCRs that will be used in creation data.
    ///
    /// # Errors
    /// * if either of the slices is larger than the maximum size of the native objects, a
    ///   `WrongParamSize` wrapper error is returned
    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        parent_handle: KeyHandle,
        public: Public,
        auth_value: Option<Auth>,
        sensitive_data: Option<SensitiveData>,
        outside_info: Option<Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<CreateKeyResult> {
        let input_parameters = CreateCommandInputHandler::create(
            parent_handle,
            public,
            auth_value,
            sensitive_data,
            outside_info,
            creation_pcrs,
        )?;

        let mut output_parameters = CreateCommandOutputHandler::new();

        ReturnCode::ensure_success(
            unsafe {
                Esys_Create(
                    self.mut_context(),
                    input_parameters.ffi_in_parent_handle(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    input_parameters.ffi_in_sensitive(),
                    input_parameters.ffi_in_public(),
                    input_parameters.ffi_outside_info(),
                    input_parameters.ffi_creation_pcr(),
                    output_parameters.ffi_out_private_ptr(),
                    output_parameters.ffi_out_public_ptr(),
                    output_parameters.ffi_creation_data_ptr(),
                    output_parameters.ffi_creation_hash_ptr(),
                    output_parameters.ffi_creation_ticket_ptr(),
                )
            },
            |ret| {
                error!("Error in creating derived key: {:#010X}", ret);
            },
        )?;

        output_parameters.try_into()
    }

    /// Load a previously generated key back into the TPM and return its new handle.
    pub fn load(
        &mut self,
        parent_handle: KeyHandle,
        private: Private,
        public: Public,
    ) -> Result<KeyHandle> {
        let mut object_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_Load(
                    self.mut_context(),
                    parent_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &private.into(),
                    &public.try_into()?,
                    &mut object_handle,
                )
            },
            |ret| {
                error!("Error in loading: {:#010X}", ret);
            },
        )?;
        let key_handle = KeyHandle::from(object_handle);
        self.handle_manager
            .add_handle(key_handle.into(), HandleDropAction::Flush)?;
        Ok(key_handle)
    }

    /// Load an external key into the TPM and return its new handle.
    ///
    /// # Details
    /// This command is used to load an object that is not a Protected Object into the TPM. The command allows
    /// loading of a public area or both a public and sensitive area.
    ///
    /// # Arguments
    /// * `private` - The optional sensitive portion of the object.
    /// * `public` - The public portion of the object.
    /// * `hierarchy` - The hierarchy with which the object area is associated.
    ///
    /// # Returns
    /// The handle to the loaded key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::ObjectAttributesBuilder,
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #    },
    /// #    structures::{
    /// #        Public, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
    /// #        SymmetricDefinition,
    /// #    },
    /// # };
    /// #
    /// # const KEY: [u8; 256] = [
    /// #     231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71, 185, 1,
    /// #     209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140, 23, 139, 169, 15,
    /// #     193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248, 250, 100, 115, 214, 166,
    /// #     165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45, 8, 9, 36, 202, 171, 165, 43, 208,
    /// #     186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49, 214, 235, 151, 9, 189, 174,
    /// #     144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205, 54, 9, 181, 14, 35, 246, 49,
    /// #     150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18, 223, 179, 229, 0, 204, 65, 69, 166, 180,
    /// #     11, 49, 131, 96, 163, 96, 158, 7, 109, 119, 208, 17, 237, 125, 187, 121, 94, 65, 2, 86, 105,
    /// #     68, 51, 197, 73, 108, 185, 231, 126, 199, 81, 1, 251, 211, 45, 47, 15, 113, 135, 197, 152, 239,
    /// #     180, 111, 18, 192, 136, 222, 11, 99, 41, 248, 205, 253, 209, 56, 214, 32, 225, 3, 49, 161, 58,
    /// #     57, 190, 69, 86, 95, 185, 184, 155, 76, 8, 122, 104, 81, 222, 234, 246, 40, 98, 182, 90, 160,
    /// #     111, 74, 102, 36, 148, 99, 69, 207, 214, 104, 87, 128, 238, 26, 121, 107, 166, 4, 64, 5, 210,
    /// #     164, 162, 189,
    /// # ];
    /// #
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
    /// #
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_user_with_auth(true)
    ///     .with_decrypt(false)
    ///     .with_sign_encrypt(true)
    ///     .with_restricted(false)
    ///     .build()
    ///     .expect("Failed to build object attributes");
    ///
    /// let public = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::Rsa)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_rsa_parameters(
    ///         PublicRsaParametersBuilder::new_unrestricted_signing_key(
    ///             RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    ///                 .expect("Failed to create rsa scheme"),
    ///             RsaKeyBits::Rsa2048,
    ///             Default::default(),
    ///         )
    ///         .build()
    ///         .expect("Failed to create rsa parameters for public structure"),
    ///     )
    ///     .with_rsa_unique_identifier(
    ///         PublicKeyRsa::from_bytes(&KEY[..256])
    ///             .expect("Failed to create Public RSA key from buffer"),
    ///     )
    ///     .build()
    ///     .expect("Failed to build Public structure");
    ///
    /// // Load public key into Owner hierarchy.
    /// let key_handle = context.load_external(None, public, Hierarchy::Owner)
    ///     .expect("The load_external should have returned a valid key handle.");
    /// ```
    pub fn load_external(
        &mut self,
        private: impl Into<Option<Sensitive>>,
        public: Public,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let potential_private = private.into();
        if (hierarchy != Hierarchy::Null) && potential_private.is_some() {
            error!("Only NULL hierarchy is valid in load_external when loading both private and public part.");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        let mut object_handle = ObjectHandle::None.into();
        let potential_private_in = potential_private.map(|v| v.try_into()).transpose()?;
        let public_in = public.try_into()?;
        ReturnCode::ensure_success(
            unsafe {
                Esys_LoadExternal(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    potential_private_in.as_ref().map_or_else(null, |v| v),
                    &public_in,
                    if cfg!(hierarchy_is_esys_tr) {
                        ObjectHandle::from(hierarchy).into()
                    } else {
                        TpmHandle::from(hierarchy).into()
                    },
                    &mut object_handle,
                )
            },
            |ret| {
                error!("Error in loading external object: {:#010X}", ret);
            },
        )?;

        let key_handle = KeyHandle::from(object_handle);
        self.handle_manager
            .add_handle(key_handle.into(), HandleDropAction::Flush)?;
        Ok(key_handle)
    }

    /// Read the public part of a key currently in the TPM and return it.
    pub fn read_public(&mut self, key_handle: KeyHandle) -> Result<(Public, Name, Name)> {
        let mut out_public_ptr = null_mut();
        let mut name_ptr = null_mut();
        let mut qualified_name_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ReadPublic(
                    self.mut_context(),
                    key_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut out_public_ptr,
                    &mut name_ptr,
                    &mut qualified_name_ptr,
                )
            },
            |ret| {
                error!("Error in reading public part of object: {:#010X}", ret);
            },
        )?;
        Ok((
            Public::try_from(Context::ffi_data_to_owned(out_public_ptr)?)?,
            Name::try_from(Context::ffi_data_to_owned(name_ptr)?)?,
            Name::try_from(Context::ffi_data_to_owned(qualified_name_ptr)?)?,
        ))
    }

    /// Activates a credential in a way that ensures parameters are validated.
    pub fn activate_credential(
        &mut self,
        activate_handle: KeyHandle,
        key_handle: KeyHandle,
        credential_blob: IdObject,
        secret: EncryptedSecret,
    ) -> Result<Digest> {
        let mut cert_info_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ActivateCredential(
                    self.mut_context(),
                    activate_handle.into(),
                    key_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &credential_blob.into(),
                    &secret.into(),
                    &mut cert_info_ptr,
                )
            },
            |ret| {
                error!("Error when activating credential: {:#010X}", ret);
            },
        )?;

        Digest::try_from(Context::ffi_data_to_owned(cert_info_ptr)?)
    }

    /// Perform actions to create a [IdObject] containing an activation credential.
    ///
    /// This does not use any TPM secrets, and is really just a convenience function.
    pub fn make_credential(
        &mut self,
        key_handle: KeyHandle,
        credential: Digest,
        object_name: Name,
    ) -> Result<(IdObject, EncryptedSecret)> {
        let mut credential_blob_ptr = null_mut();
        let mut secret_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_MakeCredential(
                    self.mut_context(),
                    key_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &credential.into(),
                    object_name.as_ref(),
                    &mut credential_blob_ptr,
                    &mut secret_ptr,
                )
            },
            |ret| {
                error!("Error when making credential: {:#010X}", ret);
            },
        )?;
        Ok((
            IdObject::try_from(Context::ffi_data_to_owned(credential_blob_ptr)?)?,
            EncryptedSecret::try_from(Context::ffi_data_to_owned(secret_ptr)?)?,
        ))
    }

    /// Unseal and return data from a Sealed Data Object
    pub fn unseal(&mut self, item_handle: ObjectHandle) -> Result<SensitiveData> {
        let mut out_data_ptr = null_mut();

        ReturnCode::ensure_success(
            unsafe {
                Esys_Unseal(
                    self.mut_context(),
                    item_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut out_data_ptr,
                )
            },
            |ret| {
                error!("Error in unsealing: {:#010X}", ret);
            },
        )?;
        SensitiveData::try_from(Context::ffi_data_to_owned(out_data_ptr)?)
    }

    /// Change authorization for a TPM-resident object.
    pub fn object_change_auth(
        &mut self,
        object_handle: ObjectHandle,
        parent_handle: ObjectHandle,
        new_auth: Auth,
    ) -> Result<Private> {
        let mut out_private_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ObjectChangeAuth(
                    self.mut_context(),
                    object_handle.into(),
                    parent_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &new_auth.into(),
                    &mut out_private_ptr,
                )
            },
            |ret| {
                error!("Error changing object auth: {:#010X}", ret);
            },
        )?;
        Private::try_from(Context::ffi_data_to_owned(out_private_ptr)?)
    }

    // Missing function: CreateLoaded
}
