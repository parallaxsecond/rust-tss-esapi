// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::ObjectHandle,
    handles::{handle_conversion::TryIntoNotNone, TpmHandle},
    structures::Auth,
    structures::Name,
    tss2_esys::{Esys_TR_Close, Esys_TR_FromTPMPublic, Esys_TR_GetName, Esys_TR_SetAuth},
    Context, Result, ReturnCode,
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;
use zeroize::Zeroize;

impl Context {
    /// Set the authentication value for a given object handle in the ESYS context.
    ///
    /// # Arguments
    /// * `object_handle` - The [ObjectHandle] associated with an object for which the auth is to be set.
    /// * `auth` -  The [Auth] that is to be set.
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// use tss_esapi::{handles::ObjectHandle, structures::Auth};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    ///
    /// // Sets auth for Owner to empty string.
    /// context
    ///     .tr_set_auth(ObjectHandle::Owner, Auth::default())
    ///     .expect("Failed to call tr_set_auth");
    /// ```
    pub fn tr_set_auth(&mut self, object_handle: ObjectHandle, auth: Auth) -> Result<()> {
        let mut auth_value = auth.into();
        ReturnCode::ensure_success(
            unsafe { Esys_TR_SetAuth(self.mut_context(), object_handle.into(), &auth_value) },
            |ret| {
                auth_value.buffer.zeroize();
                error!("Error when setting authentication value: {:#010X}", ret);
            },
        )
    }

    /// Retrieve the name of an object from the object handle.
    ///
    /// # Arguments
    /// * `object_handle` - Handle to the object for which the 'name' shall be retrieved.
    ///
    /// # Returns
    /// The objects name.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     constants::SessionType, handles::NvIndexTpmHandle,
    /// #     interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
    /// #     structures::{SymmetricDefinition, NvPublic},
    /// # };
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
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500401)
    /// #     .expect("Failed to create NV index tpm handle");
    /// #
    /// # // Create NV index attributes
    /// # let owner_nv_index_attributes = NvIndexAttributes::builder()
    /// #     .with_owner_write(true)
    /// #     .with_owner_read(true)
    /// #     .build()
    /// #     .expect("Failed to create owner nv index attributes");
    /// #
    /// # // Create owner nv public.
    /// # let owner_nv_public = NvPublic::builder()
    /// #     .with_nv_index(nv_index)
    /// #     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_index_attributes(owner_nv_index_attributes)
    /// #     .with_data_area_size(32)
    /// #     .build()
    /// #     .expect("Failed to build NvPublic for owner");
    /// #
    /// # // Define the NV space.
    /// # let nv_index_handle = context
    /// #     .nv_define_space(Provision::Owner, None, owner_nv_public)
    /// #     .expect("Call to nv_define_space failed");
    ///
    /// // Get the name using tr_get_name
    /// let tr_get_name_result = context.tr_get_name(nv_index_handle.into());
    ///
    /// // Get the name from the NV by calling nv_read_public
    /// let nv_read_public_result = context.nv_read_public(nv_index_handle);
    /// #
    /// # context
    /// #    .nv_undefine_space(Provision::Owner, nv_index_handle)
    /// #    .expect("Call to nv_undefine_space failed");
    /// #
    /// // Process result by comparing the names
    /// let (_public_area, expected_name) = nv_read_public_result.expect("Call to nv_read_public failed");
    /// let actual_name = tr_get_name_result.expect("Call to tr_get_name failed");
    /// assert_eq!(expected_name, actual_name);
    /// ```
    pub fn tr_get_name(&mut self, object_handle: ObjectHandle) -> Result<Name> {
        let mut name_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe { Esys_TR_GetName(self.mut_context(), object_handle.into(), &mut name_ptr) },
            |ret| {
                error!("Error in getting name: {:#010X}", ret);
            },
        )?;
        Name::try_from(Context::ffi_data_to_owned(name_ptr))
    }

    /// Used to construct an esys object from the resources inside the TPM.
    ///
    /// # Arguments
    /// * `tpm_handle` - The TPM handle that references the TPM object for which
    ///                  the ESYS object is being created.
    ///
    /// # Returns
    /// A handle to the ESYS object that was created from a TPM resource.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     constants::SessionType,
    /// #     interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
    /// #     structures::{SymmetricDefinition, NvPublic},
    /// # };
    /// use tss_esapi::{
    ///     handles::NvIndexTpmHandle,
    /// };
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
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// let nv_index = NvIndexTpmHandle::new(0x01500402)
    ///     .expect("Failed to create NV index tpm handle");
    /// #
    /// # // Create NV index attributes
    /// # let owner_nv_index_attributes = NvIndexAttributes::builder()
    /// #     .with_owner_write(true)
    /// #     .with_owner_read(true)
    /// #     .build()
    /// #     .expect("Failed to create owner nv index attributes");
    /// #
    /// # // Create owner nv public.
    /// # let owner_nv_public = NvPublic::builder()
    /// #     .with_nv_index(nv_index)
    /// #     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_index_attributes(owner_nv_index_attributes)
    /// #     .with_data_area_size(32)
    /// #     .build()
    /// #     .expect("Failed to build NvPublic for owner");
    /// #
    /// # // Define the NV space.
    /// # let nv_index_handle = context
    /// #     .nv_define_space(Provision::Owner, None, owner_nv_public)
    /// #     .expect("Call to nv_define_space failed");
    /// #
    /// # // Retrieve the name of the NV space.
    /// # let nv_read_public_result = context.nv_read_public(nv_index_handle);
    /// #
    /// # // Close the handle (remove all the metadata).
    /// # let mut handle_to_be_closed = nv_index_handle.into();
    /// # let tr_close_result = context
    /// #     .tr_close(&mut handle_to_be_closed);
    /// #
    /// // Call function without session (session can be provided in order to
    /// // verify that the public data read actually originates from this TPM).
    /// let retrieved_handle = context.execute_without_session(|ctx| {
    ///       ctx.tr_from_tpm_public(nv_index.into())
    /// })
    /// .expect("Call to tr_from_tpm_public failed.");
    /// #
    /// # // Use the retrieved handle to get the name of the object.
    /// # let tr_get_name_result = context
    /// #     .tr_get_name(retrieved_handle);
    /// #
    /// # context
    /// #    .nv_undefine_space(Provision::Owner, retrieved_handle.into())
    /// #    .expect("Call to nv_undefine_space failed");
    /// #
    /// # // Process results.
    /// # tr_close_result.expect("Call to tr_close_result failed");
    /// # let (_, expected_name) = nv_read_public_result.expect("Call to nv_read_public failed");
    /// # let actual_name = tr_get_name_result.expect("Call to tr_get_name failed");
    /// # assert_eq!(expected_name, actual_name);
    /// ```
    pub fn tr_from_tpm_public(&mut self, tpm_handle: TpmHandle) -> Result<ObjectHandle> {
        let mut object = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_TR_FromTPMPublic(
                    self.mut_context(),
                    tpm_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut object,
                )
            },
            |ret| {
                error!(
                    "Error when getting ESYS handle from TPM handle: {:#010X}",
                    ret
                );
            },
        )?;
        self.handle_manager.add_handle(
            object.into(),
            if tpm_handle.may_be_flushed() {
                HandleDropAction::Flush
            } else {
                HandleDropAction::Close
            },
        )?;
        Ok(object.into())
    }

    /// Instructs the ESAPI to release the metadata and resources allocated for a specific ObjectHandle.
    ///
    /// This is useful for cleaning up handles for which the context cannot be flushed.
    ///
    /// # Arguments
    /// * object_handle`- An [ObjectHandle] referring to an object for which all metadata and
    ///                   resources is going to be released.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     constants::SessionType, handles::NvIndexTpmHandle,
    /// #     interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
    /// #     structures::{SymmetricDefinition, NvPublic},
    /// # };
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
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// let nv_index = NvIndexTpmHandle::new(0x01500403)
    ///     .expect("Failed to create NV index tpm handle");
    /// #
    /// # // Create NV index attributes
    /// # let owner_nv_index_attributes = NvIndexAttributes::builder()
    /// #     .with_owner_write(true)
    /// #     .with_owner_read(true)
    /// #     .build()
    /// #     .expect("Failed to create owner nv index attributes");
    /// #
    /// # // Create owner nv public.
    /// # let owner_nv_public = NvPublic::builder()
    /// #     .with_nv_index(nv_index)
    /// #     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_index_attributes(owner_nv_index_attributes)
    /// #     .with_data_area_size(32)
    /// #     .build()
    /// #     .expect("Failed to build NvPublic for owner");
    /// #
    /// # // Define the NV space.
    /// # let nv_index_handle = context
    /// #     .nv_define_space(Provision::Owner, None, owner_nv_public)
    /// #     .expect("Call to nv_define_space failed");
    /// #
    /// # // Close the handle (remove all the metadata).
    /// # let mut handle_to_be_closed = nv_index_handle.into();
    /// let tr_close_result = context
    ///     .tr_close(&mut handle_to_be_closed);
    /// #
    /// # // Use the retrieved handle to get the name of the object.
    /// # let tr_get_name_result = context
    /// #     .tr_get_name(nv_index_handle.into());
    /// #
    /// # // Call function without session (session can be provided in order to
    /// # // verify that the public data read actually originates from this TPM).
    /// # let retrieved_handle = context.execute_without_session(|ctx| {
    /// #       ctx.tr_from_tpm_public(nv_index.into())
    /// # })
    /// # .expect("Call to tr_from_tpm_public failed.");
    /// #
    /// # context
    /// #    .nv_undefine_space(Provision::Owner, retrieved_handle.into())
    /// #    .expect("Call to nv_undefine_space failed");
    /// #
    /// // Process results.
    /// tr_close_result.expect("Call to tr_close failed.");
    /// # tr_get_name_result.expect_err("Calling tr_get_name with invalid handle did not result in an error.");
    /// ```
    pub fn tr_close(&mut self, object_handle: &mut ObjectHandle) -> Result<()> {
        let mut rsrc_handle = object_handle.try_into_not_none()?;
        ReturnCode::ensure_success(
            unsafe { Esys_TR_Close(self.mut_context(), &mut rsrc_handle) },
            |ret| {
                error!("Error when closing an ESYS handle: {:#010X}", ret);
            },
        )?;

        self.handle_manager.set_as_closed(*object_handle)?;
        *object_handle = ObjectHandle::from(rsrc_handle);
        Ok(())
    }

    #[cfg(has_esys_tr_get_tpm_handle)]
    /// Retrieve the `TpmHandle` stored in the given object.
    pub fn tr_get_tpm_handle(&mut self, object_handle: ObjectHandle) -> Result<TpmHandle> {
        use crate::{constants::tss::TPM2_RH_UNASSIGNED, tss2_esys::Esys_TR_GetTpmHandle};
        let mut tpm_handle = TPM2_RH_UNASSIGNED;
        ReturnCode::ensure_success(
            unsafe {
                Esys_TR_GetTpmHandle(self.mut_context(), object_handle.into(), &mut tpm_handle)
            },
            |ret| {
                error!(
                    "Error when getting TPM handle from ESYS handle: {:#010X}",
                    ret
                );
            },
        )?;
        TpmHandle::try_from(tpm_handle)
    }

    // Missing function: Esys_TR_Serialize
    // Missing function: Esys_TR_Deserialize
}
