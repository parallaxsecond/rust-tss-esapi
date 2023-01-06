// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod create_command_input;
mod create_command_output;

use crate::{
    context::handle_manager::HandleDropAction,
    handles::{KeyHandle, ObjectHandle, TpmHandle},
    interface_types::resource_handles::Hierarchy,
    structures::{
        Auth, CreateKeyResult, Data, Digest, EncryptedSecret, IdObject, Name, PcrSelectionList,
        Private, Public, Sensitive, SensitiveData,
    },
    tss2_esys::{
        Esys_ActivateCredential, Esys_Create, Esys_Load, Esys_LoadExternal, Esys_MakeCredential,
        Esys_ObjectChangeAuth, Esys_ReadPublic, Esys_Unseal,
    },
    Context, Result, ReturnCode,
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
    ///                  object to provide permanent, verifiable linkage between
    ///                  the object that is being created and some object owner data.
    /// * `creation_pcrs`- PCRs that will be used in creation data.
    ///
    /// # Errors
    /// * if either of the slices is larger than the maximum size of the native objects, a
    /// `WrongParamSize` wrapper error is returned
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
    pub fn load_external(
        &mut self,
        private: Sensitive,
        public: Public,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let mut object_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_LoadExternal(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &private.try_into()?,
                    &public.try_into()?,
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

    /// Load the public part of an external key and return its new handle.
    pub fn load_external_public(
        &mut self,
        public: Public,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let mut object_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_LoadExternal(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    null(),
                    &public.try_into()?,
                    if cfg!(hierarchy_is_esys_tr) {
                        ObjectHandle::from(hierarchy).into()
                    } else {
                        TpmHandle::from(hierarchy).into()
                    },
                    &mut object_handle,
                )
            },
            |ret| {
                error!("Error in loading external public object: {:#010X}", ret);
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
            Public::try_from(Context::ffi_data_to_owned(out_public_ptr))?,
            Name::try_from(Context::ffi_data_to_owned(name_ptr))?,
            Name::try_from(Context::ffi_data_to_owned(qualified_name_ptr))?,
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

        Digest::try_from(Context::ffi_data_to_owned(cert_info_ptr))
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
            IdObject::try_from(Context::ffi_data_to_owned(credential_blob_ptr))?,
            EncryptedSecret::try_from(Context::ffi_data_to_owned(secret_ptr))?,
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
        SensitiveData::try_from(Context::ffi_data_to_owned(out_data_ptr))
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
        Private::try_from(Context::ffi_data_to_owned(out_private_ptr))
    }

    // Missing function: CreateLoaded
}
