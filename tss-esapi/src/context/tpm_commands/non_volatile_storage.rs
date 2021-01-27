use crate::{
    context::handle_manager::HandleDropAction,
    handles::{AuthHandle, NvIndexHandle},
    interface_types::resource_handles::NvAuth,
    nv::storage::NvPublic,
    structures::{Auth, MaxNvBuffer, Name},
    tss2_esys::*,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Allocates an index in the non volatile storage.
    ///
    /// # Details
    /// This method will instruct the TPM to reserve space for an NV index
    /// with the attributes defined in the provided parameters.
    pub fn nv_define_space(
        &mut self,
        nv_auth: NvAuth,
        auth: Option<&Auth>,
        public_info: &NvPublic,
    ) -> Result<NvIndexHandle> {
        let mut object_identifier: ESYS_TR = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_NV_DefineSpace(
                self.mut_context(),
                AuthHandle::from(nv_auth).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &auth.cloned().unwrap_or_default().into(),
                &public_info.clone().try_into()?,
                &mut object_identifier,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager
                .add_handle(object_identifier.into(), HandleDropAction::Close)?;
            Ok(NvIndexHandle::from(object_identifier))
        } else {
            error!("Error when defining NV space: {}", ret);
            Err(ret)
        }
    }

    /// Deletes an index in the non volatile storage.
    ///
    /// # Details
    /// The method will instruct the TPM to remove a
    /// nv index.
    pub fn nv_undefine_space(
        &mut self,
        nv_auth: NvAuth,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_NV_UndefineSpace(
                self.mut_context(),
                AuthHandle::from(nv_auth).into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };

        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            self.handle_manager.set_as_closed(nv_index_handle.into())?;
            Ok(())
        } else {
            error!("Error when undefining NV space: {}", ret);
            Err(ret)
        }
    }

    // Missing function: UndefineSpaceSpecial

    /// Reads the public part of an nv index.
    ///
    /// # Details
    /// This method is used to read the public
    /// area and name of a nv index.
    pub fn nv_read_public(&mut self, nv_index_handle: NvIndexHandle) -> Result<(NvPublic, Name)> {
        let mut tss_nv_public_ptr = null_mut();
        let mut tss_nv_name_ptr = null_mut();
        let ret = unsafe {
            Esys_NV_ReadPublic(
                self.mut_context(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut tss_nv_public_ptr,
                &mut tss_nv_name_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let tss_nv_public = unsafe { MBox::<TPM2B_NV_PUBLIC>::from_raw(tss_nv_public_ptr) };
            let tss_nv_name = unsafe { MBox::<TPM2B_NAME>::from_raw(tss_nv_name_ptr) };
            Ok((
                NvPublic::try_from(*tss_nv_public)?,
                Name::try_from(*tss_nv_name)?,
            ))
        } else {
            error!("Error when reading NV public: {}", ret);
            Err(ret)
        }
    }

    /// Writes data to an nv index.
    ///
    /// # Details
    /// This method is used to write a value to
    /// the nv memory in the TPM.
    pub fn nv_write(
        &mut self,
        auth_handle: AuthHandle,
        nv_index_handle: NvIndexHandle,
        data: &MaxNvBuffer,
        offset: u16,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_NV_Write(
                self.mut_context(),
                auth_handle.into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &data.clone().into(),
                offset,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when writing NV: {}", ret);
            Err(ret)
        }
    }

    // Missing function: NV_Increment
    // Missing function: NV_Extend
    // Missing function: NV_SetBits
    // Missing function: NV_WriteLock
    // Missing function: NV_GlobalWriteLock

    /// Reads data from the nv index.
    ///
    /// # Details
    /// This method is used to read a value from an area in
    /// NV memory of the TPM.
    pub fn nv_read(
        &mut self,
        auth_handle: AuthHandle,
        nv_index_handle: NvIndexHandle,
        size: u16,
        offset: u16,
    ) -> Result<MaxNvBuffer> {
        let mut tss_max_nv_buffer_ptr = null_mut();
        let ret = unsafe {
            Esys_NV_Read(
                self.mut_context(),
                auth_handle.into(),
                nv_index_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                size,
                offset,
                &mut tss_max_nv_buffer_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let tss_max_nv_buffer =
                unsafe { MBox::<TPM2B_MAX_NV_BUFFER>::from_raw(tss_max_nv_buffer_ptr) };
            Ok(MaxNvBuffer::try_from(*tss_max_nv_buffer)?)
        } else {
            error!("Error when reading NV: {}", ret);
            Err(ret)
        }
    }

    // Missing function: NV_ReadLock
    // Missing function: NV_ChangeAuth
    // Missing function: NV_Certify
}
