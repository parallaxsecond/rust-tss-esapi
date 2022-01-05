// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::{KeyHandle, ObjectHandle, TpmHandle},
    interface_types::resource_handles::Hierarchy,
    structures::{
        Auth, CreateKeyResult, CreationData, CreationTicket, Data, Digest, EncryptedSecret,
        IDObject, Name, PcrSelectionList, Private, Public, Sensitive, SensitiveData,
    },
    tss2_esys::*,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
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
        public: &Public,
        auth_value: Option<&Auth>,
        sensitive_data: Option<&SensitiveData>,
        outside_info: Option<&Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<CreateKeyResult> {
        let sensitive_create = TPM2B_SENSITIVE_CREATE {
            size: std::mem::size_of::<TPMS_SENSITIVE_CREATE>()
                .try_into()
                .unwrap(), // will not fail on targets of at least 16 bits
            sensitive: TPMS_SENSITIVE_CREATE {
                userAuth: auth_value.cloned().unwrap_or_default().into(),
                data: sensitive_data.cloned().unwrap_or_default().into(),
            },
        };
        let creation_pcrs = PcrSelectionList::list_from_option(creation_pcrs);

        let mut out_public_ptr = null_mut();
        let mut out_private_ptr = null_mut();
        let mut creation_data_ptr = null_mut();
        let mut creation_hash_ptr = null_mut();
        let mut creation_ticket_ptr = null_mut();

        let ret = unsafe {
            Esys_Create(
                self.mut_context(),
                parent_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &sensitive_create,
                &public.clone().try_into()?,
                &outside_info.cloned().unwrap_or_default().into(),
                &creation_pcrs.into(),
                &mut out_private_ptr,
                &mut out_public_ptr,
                &mut creation_data_ptr,
                &mut creation_hash_ptr,
                &mut creation_ticket_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_private_owned = unsafe { MBox::from_raw(out_private_ptr) };
            let out_public_owned = unsafe { MBox::from_raw(out_public_ptr) };
            let creation_data_owned = unsafe { MBox::from_raw(creation_data_ptr) };
            let creation_hash_owned = unsafe { MBox::from_raw(creation_hash_ptr) };
            let creation_ticket_owned = unsafe { MBox::from_raw(creation_ticket_ptr) };
            Ok(CreateKeyResult {
                out_private: Private::try_from(*out_private_owned)?,
                out_public: Public::try_from(*out_public_owned)?,
                creation_data: CreationData::try_from(*creation_data_owned)?,
                creation_hash: Digest::try_from(*creation_hash_owned)?,
                creation_ticket: CreationTicket::try_from(*creation_ticket_owned)?,
            })
        } else {
            error!("Error in creating derived key: {}", ret);
            Err(ret)
        }
    }

    /// Load a previously generated key back into the TPM and return its new handle.
    pub fn load(
        &mut self,
        parent_handle: KeyHandle,
        private: Private,
        public: &Public,
    ) -> Result<KeyHandle> {
        let mut esys_key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_Load(
                self.mut_context(),
                parent_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &private.into(),
                &public.clone().try_into()?,
                &mut esys_key_handle,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let key_handle = KeyHandle::from(esys_key_handle);
            self.handle_manager
                .add_handle(key_handle.into(), HandleDropAction::Flush)?;
            Ok(key_handle)
        } else {
            error!("Error in loading: {}", ret);
            Err(ret)
        }
    }

    /// Load an external key into the TPM and return its new handle.
    pub fn load_external(
        &mut self,
        private: Sensitive,
        public: &Public,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let mut esys_key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_LoadExternal(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &private.try_into()?,
                &public.clone().try_into()?,
                if cfg!(tpm2_tss_version = "3") {
                    ObjectHandle::from(hierarchy).into()
                } else {
                    TpmHandle::from(hierarchy).into()
                },
                &mut esys_key_handle,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let key_handle = KeyHandle::from(esys_key_handle);
            self.handle_manager
                .add_handle(key_handle.into(), HandleDropAction::Flush)?;
            Ok(key_handle)
        } else {
            error!("Error in loading external object: {}", ret);
            Err(ret)
        }
    }

    /// Load the public part of an external key and return its new handle.
    pub fn load_external_public(
        &mut self,
        public: &Public,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let mut esys_key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_LoadExternal(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                null(),
                &public.clone().try_into()?,
                if cfg!(tpm2_tss_version = "3") {
                    ObjectHandle::from(hierarchy).into()
                } else {
                    TpmHandle::from(hierarchy).into()
                },
                &mut esys_key_handle,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let key_handle = KeyHandle::from(esys_key_handle);
            self.handle_manager
                .add_handle(key_handle.into(), HandleDropAction::Flush)?;
            Ok(key_handle)
        } else {
            error!("Error in loading external public object: {}", ret);
            Err(ret)
        }
    }

    /// Read the public part of a key currently in the TPM and return it.
    pub fn read_public(&mut self, key_handle: KeyHandle) -> Result<(Public, Name, Name)> {
        let mut out_public_ptr = null_mut();
        let mut out_name_ptr = null_mut();
        let mut out_qualified_name_ptr = null_mut();
        let ret = unsafe {
            Esys_ReadPublic(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut out_public_ptr,
                &mut out_name_ptr,
                &mut out_qualified_name_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_name_owned = unsafe { MBox::from_raw(out_name_ptr) };
            let out_qualified_name_owned = unsafe { MBox::from_raw(out_qualified_name_ptr) };
            let out_public_owned = unsafe { MBox::<TPM2B_PUBLIC>::from_raw(out_public_ptr) };

            Ok((
                Public::try_from(*out_public_owned)?,
                Name::try_from(*out_name_owned)?,
                Name::try_from(*out_qualified_name_owned)?,
            ))
        } else {
            error!("Error in reading public part of object: {}", ret);
            Err(ret)
        }
    }

    /// Activates a credential in a way that ensures parameters are validated.
    pub fn activate_credential(
        &mut self,
        activate_handle: KeyHandle,
        key_handle: KeyHandle,
        credential_blob: IDObject,
        secret: EncryptedSecret,
    ) -> Result<Digest> {
        let mut out_cert_info_ptr = null_mut();
        let ret = unsafe {
            Esys_ActivateCredential(
                self.mut_context(),
                activate_handle.into(),
                key_handle.into(),
                self.required_session_1()?,
                self.required_session_2()?,
                self.optional_session_3(),
                &credential_blob.into(),
                &secret.into(),
                &mut out_cert_info_ptr,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_cert_info_owned = unsafe { MBox::<TPM2B_DIGEST>::from_raw(out_cert_info_ptr) };

            Ok(Digest::try_from(*out_cert_info_owned)?)
        } else {
            error!("Error when activating credential: {}", ret);
            Err(ret)
        }
    }

    /// Perform actions to create a [IDObject] containing an activation credential.
    ///
    /// This does not use any TPM secrets, and is really just a convenience function.
    pub fn make_credential(
        &mut self,
        key_handle: KeyHandle,
        credential: Digest,
        object_name: Name,
    ) -> Result<(IDObject, EncryptedSecret)> {
        let mut out_credential_blob = null_mut();
        let mut out_secret = null_mut();
        let ret = unsafe {
            Esys_MakeCredential(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &credential.into(),
                object_name.as_ref(),
                &mut out_credential_blob,
                &mut out_secret,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_credential_blob =
                unsafe { MBox::<TPM2B_ID_OBJECT>::from_raw(out_credential_blob) };
            let out_secret = unsafe { MBox::<TPM2B_ENCRYPTED_SECRET>::from_raw(out_secret) };

            Ok((
                IDObject::try_from(*out_credential_blob)?,
                EncryptedSecret::try_from(*out_secret)?,
            ))
        } else {
            error!("Error when making credential: {}", ret);
            Err(ret)
        }
    }

    /// Unseal and return data from a Sealed Data Object
    pub fn unseal(&mut self, item_handle: ObjectHandle) -> Result<SensitiveData> {
        let mut out_data = null_mut();

        let ret = unsafe {
            Esys_Unseal(
                self.mut_context(),
                item_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut out_data,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_data = unsafe { MBox::from_raw(out_data) };
            Ok(SensitiveData::try_from(*out_data)?)
        } else {
            error!("Error in unsealing: {}", ret);
            Err(ret)
        }
    }

    /// Change authorization for a TPM-resident object.
    pub fn object_change_auth(
        &mut self,
        object_handle: ObjectHandle,
        parent_handle: ObjectHandle,
        new_auth: Auth,
    ) -> Result<Private> {
        let mut out_private = null_mut();
        let ret = unsafe {
            Esys_ObjectChangeAuth(
                self.mut_context(),
                object_handle.into(),
                parent_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &new_auth.into(),
                &mut out_private,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let out_private = unsafe { MBox::from_raw(out_private) };
            let out_private = Private::try_from(*out_private)?;
            Ok(out_private)
        } else {
            error!("Error changing object auth: {}", ret);
            Err(ret)
        }
    }

    // Missing function: CreateLoaded
}
