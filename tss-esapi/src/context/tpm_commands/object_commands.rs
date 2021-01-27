use crate::{
    context::handle_manager::HandleDropAction,
    handles::{KeyHandle, ObjectHandle, TpmHandle},
    interface_types::resource_handles::Hierarchy,
    structures::{
        Auth, CreateKeyResult, CreationData, CreationTicket, Data, Digest, EncryptedSecret,
        IDObject, Name, PcrSelectionList, Private, SensitiveData,
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
    /// # Errors
    /// * if either of the slices is larger than the maximum size of the native objects, a
    /// `WrongParamSize` wrapper error is returned
    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        parent_handle: KeyHandle,
        public: &TPM2B_PUBLIC,
        auth_value: Option<&Auth>,
        initial_data: Option<&SensitiveData>,
        outside_info: Option<&Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<CreateKeyResult> {
        let sensitive_create = TPM2B_SENSITIVE_CREATE {
            size: std::mem::size_of::<TPMS_SENSITIVE_CREATE>()
                .try_into()
                .unwrap(), // will not fail on targets of at least 16 bits
            sensitive: TPMS_SENSITIVE_CREATE {
                userAuth: auth_value.cloned().unwrap_or_default().into(),
                data: initial_data.cloned().unwrap_or_default().into(),
            },
        };
        let creation_pcrs = PcrSelectionList::list_from_option(creation_pcrs);

        let mut outpublic = null_mut();
        let mut outprivate = null_mut();
        let mut creation_data = null_mut();
        let mut creation_hash = null_mut();
        let mut creation_ticket = null_mut();

        let ret = unsafe {
            Esys_Create(
                self.mut_context(),
                parent_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &sensitive_create,
                public,
                &outside_info.cloned().unwrap_or_default().into(),
                &creation_pcrs.into(),
                &mut outprivate,
                &mut outpublic,
                &mut creation_data,
                &mut creation_hash,
                &mut creation_ticket,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let outprivate = unsafe { MBox::from_raw(outprivate) };
            let outprivate = Private::try_from(*outprivate)?;
            let outpublic = unsafe { MBox::from_raw(outpublic) };
            let creation_data = unsafe { MBox::from_raw(creation_data) };
            let creation_hash = unsafe { MBox::from_raw(creation_hash) };
            let creation_ticket = unsafe { MBox::from_raw(creation_ticket) };

            let creation_data = CreationData::try_from(*creation_data)?;
            let creation_hash = Digest::try_from(*creation_hash)?;
            let creation_ticket = CreationTicket::try_from(*creation_ticket)?;
            Ok(CreateKeyResult {
                out_private: outprivate,
                out_public: *outpublic,
                creation_data,
                creation_hash,
                creation_ticket,
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
        public: TPM2B_PUBLIC,
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
                &public,
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
        private: &TPM2B_SENSITIVE,
        public: &TPM2B_PUBLIC,
        hierarchy: Hierarchy,
    ) -> Result<KeyHandle> {
        let mut esys_key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_LoadExternal(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                private,
                public,
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
        public: &TPM2B_PUBLIC,
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
                public,
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
    pub fn read_public(&mut self, key_handle: KeyHandle) -> Result<(TPM2B_PUBLIC, Name, Name)> {
        let mut public = null_mut();
        let mut name = null_mut();
        let mut qualified_name = null_mut();
        let ret = unsafe {
            Esys_ReadPublic(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut public,
                &mut name,
                &mut qualified_name,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let name = unsafe { MBox::from_raw(name) };
            let qualified_name = unsafe { MBox::from_raw(qualified_name) };
            let public = unsafe { MBox::<TPM2B_PUBLIC>::from_raw(public) };

            let name = Name::try_from(*name)?;
            let qualified_name = Name::try_from(*qualified_name)?;

            Ok((*public, name, qualified_name))
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
        let mut out_cert_info = null_mut();
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
                &mut out_cert_info,
            )
        };

        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_cert_info = unsafe { MBox::<TPM2B_DIGEST>::from_raw(out_cert_info) };

            Ok(Digest::try_from(*out_cert_info)?)
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
                &object_name.try_into()?,
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
            error!("Error changing hierarchy auth: {}", ret);
            Err(ret)
        }
    }

    // Missing function: CreateLoaded
}
