// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::ObjectHandle,
    handles::{handle_conversion::TryIntoNotNone, TpmHandle},
    structures::Auth,
    structures::Name,
    tss2_esys::{
        Esys_TR_Close, Esys_TR_FromTPMPublic, Esys_TR_GetName, Esys_TR_SetAuth, ESYS_TR,
        ESYS_TR_NONE, TPM2B_NAME,
    },
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::TryFrom;
use std::ptr::null_mut;
use zeroize::Zeroize;

impl Context {
    /// Set the authentication value for a given object handle in the ESYS context.
    pub fn tr_set_auth(&mut self, object_handle: ObjectHandle, auth: &Auth) -> Result<()> {
        let mut tss_auth = auth.clone().into();
        let ret = unsafe { Esys_TR_SetAuth(self.mut_context(), object_handle.into(), &tss_auth) };
        tss_auth.buffer.zeroize();
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when setting authentication value: {}", ret);
            Err(ret)
        }
    }

    /// Retrieve the name of an object from the object handle
    pub fn tr_get_name(&mut self, object_handle: ObjectHandle) -> Result<Name> {
        let mut name = null_mut();
        let ret = unsafe { Esys_TR_GetName(self.mut_context(), object_handle.into(), &mut name) };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let tss_name = unsafe { MBox::<TPM2B_NAME>::from_raw(name) };
            Ok(Name::try_from(*tss_name)?)
        } else {
            error!("Error in getting name: {}", ret);
            Err(ret)
        }
    }

    /// Used to construct an esys object from the resources inside the TPM.
    pub fn tr_from_tpm_public(&mut self, tpm_handle: TpmHandle) -> Result<ObjectHandle> {
        let mut esys_object_handle: ESYS_TR = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_TR_FromTPMPublic(
                self.mut_context(),
                tpm_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut esys_object_handle,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let object_handle = ObjectHandle::from(esys_object_handle);
            self.handle_manager.add_handle(
                object_handle,
                if tpm_handle.may_be_flushed() {
                    HandleDropAction::Flush
                } else {
                    HandleDropAction::Close
                },
            )?;
            Ok(object_handle)
        } else {
            error!("Error when getting ESYS handle from TPM handle: {}", ret);
            Err(ret)
        }
    }

    /// Instructs the ESAPI to release the metadata and resources allocated for a specific ObjectHandle.
    ///
    /// This is useful for cleaning up handles for which the context cannot be flushed.
    pub fn tr_close(&mut self, object_handle: &mut ObjectHandle) -> Result<()> {
        let mut tss_esys_object_handle = object_handle.try_into_not_none()?;
        let ret = unsafe { Esys_TR_Close(self.mut_context(), &mut tss_esys_object_handle) };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager.set_as_closed(*object_handle)?;
            *object_handle = ObjectHandle::from(tss_esys_object_handle);
            Ok(())
        } else {
            error!("Error when closing an ESYS handle: {}", ret);
            Err(ret)
        }
    }

    // Missing function: Esys_TR_Serialize
    // Missing function: Esys_TR_Deserialize
}
