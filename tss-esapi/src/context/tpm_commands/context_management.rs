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
    /// ```rust, no_run
    /// use tss_esapi::{
    ///     Context, Tcti, structures::Auth,
    ///     constants::{
    ///         algorithm::{Cipher, HashingAlgorithm},
    ///         tss::{TPMA_SESSION_DECRYPT, TPMA_SESSION_ENCRYPT},
    ///         types::session::SessionType,
    ///     },
    ///     interface_types::resource_handles::Hierarchy,
    ///     utils::{create_unrestricted_signing_rsa_public, AsymSchemeUnion},
    ///     session::SessionAttributesBuilder,
    /// };
    /// use std::convert::TryFrom;
    /// use std::str::FromStr;
    ///
    /// // Create context that uses Device TCTI.
    /// let mut context = unsafe {
    ///     Context::new(Tcti::Device(Default::default())).expect("Failed to create Context")
    /// };
    ///
    /// // Create session for a key
    /// let session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         Cipher::aes_256_cfb(),
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
    /// # Returns
    /// If the input object_handle was transient object then it will be made
    /// persistent and the returned ObjectHandle will refer to this object.
    ///
    /// If the input object_handle refers to a presistent object the returned
    /// value will be ObjectHandle::None and the input object_handle will not
    /// be valid after this call is made.
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
