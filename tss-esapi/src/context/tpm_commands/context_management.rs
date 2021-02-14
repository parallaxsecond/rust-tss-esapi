use crate::{
    context::handle_manager::HandleDropAction,
    handles::{handle_conversion::TryIntoNotNone, AuthHandle, ObjectHandle, PersistentTpmHandle},
    interface_types::{dynamic_handles::Persistent, resource_handles::Provision},
    tss2_esys::*,
    utils::TpmsContext,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Save the context of an object from the TPM and return it.
    ///
    /// # Errors
    /// * if conversion from `TPMS_CONTEXT` to `TpmsContext` fails, a `WrongParamSize` error will
    /// be returned
    pub fn context_save(&mut self, handle: ObjectHandle) -> Result<TpmsContext> {
        let mut context = null_mut();
        let ret = unsafe { Esys_ContextSave(self.mut_context(), handle.into(), &mut context) };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let context = unsafe { MBox::<TPMS_CONTEXT>::from_raw(context) };
            Ok((*context).try_into()?)
        } else {
            error!("Error in saving context: {}", ret);
            Err(ret)
        }
    }

    /// Load a previously saved context into the TPM and return the object handle.
    ///
    /// # Errors
    /// * if conversion from `TpmsContext` to the native `TPMS_CONTEXT` fails, a `WrongParamSize`
    /// error will be returned
    pub fn context_load(&mut self, context: TpmsContext) -> Result<ObjectHandle> {
        let mut esys_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_ContextLoad(
                self.mut_context(),
                &TPMS_CONTEXT::try_from(context)?,
                &mut esys_handle,
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let object_handle = ObjectHandle::from(esys_handle);
            self.handle_manager
                .add_handle(object_handle, HandleDropAction::Flush)?;
            Ok(object_handle)
        } else {
            error!("Error in loading context: {}", ret);
            Err(ret)
        }
    }

    /// Flush the context of an object from the TPM.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, Tcti, structures::Auth,
    /// #     constants::{
    /// #         tss::{TPMA_SESSION_DECRYPT, TPMA_SESSION_ENCRYPT},
    /// #         SessionType,
    /// #     },
    /// #     interface_types::{resource_handles::Hierarchy, algorithm::HashingAlgorithm},
    /// #     utils::{create_unrestricted_signing_rsa_public, AsymSchemeUnion},
    /// #     attributes::SessionAttributesBuilder,
    /// #     structures::SymmetricDefinition,
    /// # };
    /// # use std::convert::TryFrom;
    /// # use std::str::FromStr;
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    ///
    /// // Create session for a key
    /// let session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Failed to create session")
    ///     .expect("Recived invalid handle");
    /// let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    ///     .with_decrypt(true)
    ///     .with_encrypt(true)
    ///     .build();
    /// context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    ///     .expect("Failed to set attributes on session");
    ///
    /// // Create public area for a rsa key
    /// let public_area = create_unrestricted_signing_rsa_public(
    ///         AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
    ///         2048,
    ///         0,
    ///     )
    ///     .expect("Failed to create rsa public area");
    ///
    /// // Execute context methods using the session
    /// context.execute_with_session(Some(session), |ctx| {
    ///     let random_digest = ctx.get_random(16)
    ///         .expect("Call to get_random failed");
    ///     let key_auth = Auth::try_from(random_digest.value().to_vec())
    ///         .expect("Failed to create Auth");
    ///     let key_handle = ctx
    ///         .create_primary(
    ///             Hierarchy::Owner,
    ///             &public_area,
    ///             Some(&key_auth),
    ///             None,
    ///             None,
    ///             None,
    ///         )
    ///         .expect("Failed to create primary key")
    ///         .key_handle;
    ///
    ///         // Flush the context of the key.
    ///         ctx.flush_context(key_handle.into()).expect("Call to flush_context failed");
    ///         assert!(ctx.read_public(key_handle).is_err());
    /// })
    /// ```
    pub fn flush_context(&mut self, handle: ObjectHandle) -> Result<()> {
        let ret = unsafe { Esys_FlushContext(self.mut_context(), handle.try_into_not_none()?) };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager.set_as_flushed(handle)?;
            Ok(())
        } else {
            error!("Error in flushing context: {}", ret);
            Err(ret)
        }
    }

    /// Evicts persistent objects or allows certain transient objects
    /// to be made peristent.
    ///
    /// # Details
    /// In order to be able to perform this action an authorization
    /// session is required.
    ///
    /// # Arguments
    /// * `auth` - An a handle used for authorization that is limited to the ones
    ///            specified in [Provision].
    /// * `object_handle` - The handle of a loaded object.
    /// * `persistant` - If the `object_handle` is transient object then this
    ///                  then this will become the persistant handle of that
    ///                  object. If the `object_handle` refers to a persistant
    ///                  object then this shall be the persistant handle of that
    ///                  object.
    ///
    /// # Returns
    /// If the input `object_handle` was transient object then it will be made
    /// persistent and the returned [ObjectHandle] will refer to the persistent
    /// object.
    ///
    /// If the input `object_handle` refers to a presistent object the returned
    /// value will be ObjectHandle::None and the input `object_handle` will not
    /// be valid after this call is made.
    ///
    /// # Example
    ///
    /// Make transient object peristent:
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, Tcti, Result,
    /// #     constants::{
    /// #         SessionType, CapabilityType,
    /// #         tss::TPM2_PERSISTENT_FIRST,
    /// #     },
    /// #     handles::PcrHandle,
    /// #     structures::{Digest, CapabilityData, Auth},
    /// #     interface_types::{
    /// #       resource_handles::Hierarchy,
    /// #     },
    /// #     handles::{ObjectHandle, TpmHandle, PersistentTpmHandle},
    /// #     utils::create_restricted_decryption_rsa_public,
    /// #     tss2_esys::TPM2_HANDLE,
    /// #     abstraction::cipher::Cipher,
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// # // Create persistent TPM handle with
    /// # let persistent_tpm_handle =
    /// #    PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))
    /// #        .expect("Failed to create Persistant TPM handle");
    /// # // -----> REMOVE ANY PREVIOUS HANDLES <---------------
    /// # let mut property = TPM2_PERSISTENT_FIRST;
    /// # while let Ok((capability_data, more_data_available)) =
    /// #     context.get_capability(CapabilityType::Handles, property, 1)
    /// # {
    /// #     if let CapabilityData::Handles(persistent_handles) = capability_data {
    /// #         if let Some(&retrieved_persistent_handle) = persistent_handles.first() {
    /// #             if retrieved_persistent_handle == persistent_tpm_handle.into() {
    /// #                 let handle = context
    /// #                     .tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
    /// #                     .expect("Failed to retrieve handle from TPM");
    /// #                 context.execute_with_session(Some(tss_esapi::session::Session::Password), |ctx| {
    /// #                     ctx
    /// #                           .evict_control(
    /// #                               tss_esapi::interface_types::resource_handles::Provision::Owner,
    /// #                               handle,
    /// #                               tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(persistent_tpm_handle),
    /// #                           )
    /// #                           .expect("Failed to evict persitent handle")
    /// #                 });
    /// #                 break;
    /// #             }
    /// #             if more_data_available {
    /// #                 property = TPM2_HANDLE::from(retrieved_persistent_handle) + 1;
    /// #             }
    /// #         }
    /// #     }
    /// #     if !more_data_available {
    /// #         break;
    /// #     }
    /// # }
    /// # let transient_object_handle = context.execute_with_session(Some(Session::Password), |ctx| {
    /// #    // Create primary key handle
    /// #    let auth_value_primary = Auth::try_from(vec![1, 2, 3, 4, 5])
    /// #        .expect("Failed to crate auth value for primary key");
    /// #    ctx
    /// #        .create_primary(
    /// #            Hierarchy::Owner,
    /// #            &create_restricted_decryption_rsa_public(Cipher::aes_256_cfb(), 2048, 0)
    /// #               .expect("Failed to Public structure for key"),
    /// #            Some(auth_value_primary).as_ref(),
    /// #            None,
    /// #            None,
    /// #            None,
    /// #        )
    /// #        .map(|v| ObjectHandle::from(v.key_handle))
    /// #        .expect("Failed to create primary key")
    /// # });
    /// use tss_esapi::{
    ///     interface_types::{resource_handles::Provision, dynamic_handles::Persistent},
    ///     session::Session,
    /// };
    /// // Create interface type Persistent by using the persistent tpm handle.
    /// let persistent = Persistent::Persistent(persistent_tpm_handle);
    /// // Make transient_object_handle persistent.
    /// // An authorization session is required!
    /// let mut persistent_object_handle = context.execute_with_session(Some(Session::Password), |ctx| {
    ///     ctx
    ///         .evict_control(Provision::Owner, transient_object_handle.into(), persistent)
    ///         .expect("Failed to make the transient_object_handle handle persistent")
    /// });
    /// # assert_ne!(persistent_object_handle, ObjectHandle::Null);
    /// # assert_ne!(persistent_object_handle, ObjectHandle::None);
    /// # // Flush out the transient_object_handle
    /// # context
    /// #     .flush_context(ObjectHandle::from(transient_object_handle))
    /// #     .expect("Failed to flush context");
    /// # // Close the persistant_handle returned by evict_control
    /// # context
    /// #     .tr_close(&mut persistent_object_handle)
    /// #     .expect("Failed to close persistant handle");
    /// # // Retrieve the handle from the tpm again.
    /// # let retireved_persistant_handle = context.execute_without_session(|ctx| {
    /// #     ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
    /// #         .expect("Failed to load the persistant handle")
    /// # });
    /// # // Evict the persitent handle from the tpm
    /// # let _ = context.execute_with_session(Some(Session::Password), |ctx| {
    /// #   ctx
    /// #       .evict_control(Provision::Owner, retireved_persistant_handle, persistent)
    /// #       .expect("Failed to evict persistent handle")
    /// # });
    /// # assert_ne!(retireved_persistant_handle, ObjectHandle::None);
    /// ```
    ///
    /// Make persistent object transient
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, Tcti, Result,
    /// #     constants::{
    /// #         SessionType, CapabilityType,
    /// #         tss::TPM2_PERSISTENT_FIRST,
    /// #     },
    /// #     handles::PcrHandle,
    /// #     structures::{Digest, CapabilityData, Auth},
    /// #     interface_types::{
    /// #       resource_handles::Hierarchy,
    /// #     },
    /// #     handles::{ObjectHandle, TpmHandle, PersistentTpmHandle},
    /// #     utils::create_restricted_decryption_rsa_public,
    /// #     tss2_esys::TPM2_HANDLE,
    /// #     abstraction::cipher::Cipher,
    /// # };
    /// # use std::{env, str::FromStr, convert::TryFrom};
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// # // Create persistent TPM handle with
    /// # let persistent_tpm_handle =
    /// #    PersistentTpmHandle::new(u32::from_be_bytes([0x81, 0x00, 0x00, 0x01]))
    /// #        .expect("Failed to create Persistant TPM handle");
    /// # // -----> REMOVE ANY PREVIOUS HANDLES <---------------
    /// # let mut property = TPM2_PERSISTENT_FIRST;
    /// # while let Ok((capability_data, more_data_available)) =
    /// #     context.get_capability(CapabilityType::Handles, property, 1)
    /// # {
    /// #     if let CapabilityData::Handles(persistent_handles) = capability_data {
    /// #         if let Some(&retrieved_persistent_handle) = persistent_handles.first() {
    /// #             if retrieved_persistent_handle == persistent_tpm_handle.into() {
    /// #                 let handle = context
    /// #                     .tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
    /// #                     .expect("Failed to retrieve handle from TPM");
    /// #                 context.execute_with_session(Some(tss_esapi::session::Session::Password), |ctx| {
    /// #                     ctx
    /// #                           .evict_control(
    /// #                               tss_esapi::interface_types::resource_handles::Provision::Owner,
    /// #                               handle,
    /// #                               tss_esapi::interface_types::dynamic_handles::Persistent::Persistent(persistent_tpm_handle),
    /// #                           )
    /// #                           .expect("Failed to evict persitent handle")
    /// #                 });
    /// #                 break;
    /// #             }
    /// #             if more_data_available {
    /// #                 property = TPM2_HANDLE::from(retrieved_persistent_handle) + 1;
    /// #             }
    /// #         }
    /// #     }
    /// #     if !more_data_available {
    /// #         break;
    /// #     }
    /// # }
    /// # let transient_object_handle = context.execute_with_session(Some(Session::Password), |ctx| {
    /// #    // Create primary key handle
    /// #    let auth_value_primary = Auth::try_from(vec![1, 2, 3, 4, 5])
    /// #        .expect("Failed to crate auth value for primary key");
    /// #    ctx
    /// #        .create_primary(
    /// #            Hierarchy::Owner,
    /// #            &create_restricted_decryption_rsa_public(Cipher::aes_256_cfb(), 2048, 0)
    /// #               .expect("Failed to Public structure for key"),
    /// #            Some(auth_value_primary).as_ref(),
    /// #            None,
    /// #            None,
    /// #            None,
    /// #        )
    /// #        .map(|v| ObjectHandle::from(v.key_handle))
    /// #        .expect("Failed to create primary key")
    /// # });
    /// use tss_esapi::{
    ///     interface_types::{resource_handles::Provision, dynamic_handles::Persistent},
    ///     session::Session,
    /// };
    /// // Create interface type Persistent by using the persistent tpm handle.
    /// let persistent = Persistent::Persistent(persistent_tpm_handle);
    /// # // Evict control to make transient_object_handle persistent.
    /// # // An authorization session is required!
    /// # let mut persistent_object_handle = context.execute_with_session(Some(Session::Password), |ctx| {
    /// #   ctx
    /// #       .evict_control(Provision::Owner, transient_object_handle.into(), persistent)
    /// #       .expect("Failed to make the transient_object_handle handle persistent")
    /// # });
    /// # assert_ne!(persistent_object_handle, ObjectHandle::Null);
    /// # assert_ne!(persistent_object_handle, ObjectHandle::None);
    /// # // Flush out the transient_object_handle
    /// # context
    /// #     .flush_context(ObjectHandle::from(transient_object_handle))
    /// #     .expect("Failed to flush context");
    /// # // Close the persistant_handle returned by evict_control
    /// # context
    /// #     .tr_close(&mut persistent_object_handle)
    /// #     .expect("Failed to close persistant handle");
    /// # // Retrieve the handle from the tpm again.
    /// # let retireved_persistant_handle = context.execute_without_session(|ctx| {
    /// #     ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent_tpm_handle))
    /// #         .expect("Failed to load the persistant handle")
    /// # });
    /// // Evict the persitent handle from the tpm
    /// // An authorization session is required!
    /// let _ = context.execute_with_session(Some(Session::Password), |ctx| {
    ///     ctx
    ///         .evict_control(Provision::Owner, retireved_persistant_handle, persistent)
    ///         .expect("Failed to evict persistent handle")
    /// });
    /// # assert_ne!(retireved_persistant_handle, ObjectHandle::None);
    /// ```
    pub fn evict_control(
        &mut self,
        auth: Provision,
        object_handle: ObjectHandle,
        persistent: Persistent,
    ) -> Result<ObjectHandle> {
        let mut esys_object_handle: ESYS_TR = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_EvictControl(
                self.mut_context(),
                AuthHandle::from(auth).into(),
                object_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                PersistentTpmHandle::from(persistent).into(),
                &mut esys_object_handle,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let new_object_handle = ObjectHandle::from(esys_object_handle);
            // If you look at the specification and see that it says ESYS_TR_NULL
            // then that is an error in the spec. ESYS_TR_NULL was renamed to
            // ESYS_TR NONE.
            if !new_object_handle.is_none() {
                self.handle_manager
                    .add_handle(new_object_handle, HandleDropAction::Close)?;
            } else {
                self.handle_manager.set_as_closed(object_handle)?;
            }

            Ok(new_object_handle)
        } else {
            error!("Error in evict control: {}", ret);
            Err(ret)
        }
    }
}
