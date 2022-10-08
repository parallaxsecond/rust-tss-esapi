// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    context::handle_manager::HandleDropAction,
    handles::{AuthHandle, NvIndexHandle, ObjectHandle},
    interface_types::resource_handles::{NvAuth, Provision},
    structures::{Auth, MaxNvBuffer, Name, NvPublic},
    tss2_esys::{
        Esys_NV_DefineSpace, Esys_NV_Increment, Esys_NV_Read, Esys_NV_ReadPublic,
        Esys_NV_UndefineSpace, Esys_NV_Write,
    },
    Context, Result, ReturnCode,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Allocates an index in the non volatile storage.
    ///
    /// # Details
    /// This method will instruct the TPM to reserve space for an NV index
    /// with the attributes defined in the provided parameters.
    ///
    /// Please beware
    /// that this method requires an authorization session handle to be present.
    ///
    /// # Arguments
    /// * `nv_auth` - The [Provision] used for authorization.
    /// * `auth` - The authorization value.
    /// * `public_info` - The public parameters of the NV area.
    ///
    /// # Returns
    /// A [NvIndexHandle] associated with the NV memory that
    /// was defined.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::SessionAttributes, constants::SessionType,
    /// #     structures::SymmetricDefinition,
    /// # };
    /// use tss_esapi::{
    ///      handles::NvIndexTpmHandle, attributes::NvIndexAttributes, structures::NvPublic,
    ///      interface_types::{algorithm::HashingAlgorithm, resource_handles::Provision},
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
    /// let nv_index = NvIndexTpmHandle::new(0x01500022)
    ///     .expect("Failed to create NV index tpm handle");
    ///
    /// // Create NV index attributes
    /// let owner_nv_index_attributes = NvIndexAttributes::builder()
    ///     .with_owner_write(true)
    ///     .with_owner_read(true)
    ///     .build()
    ///     .expect("Failed to create owner nv index attributes");
    ///
    /// // Create owner nv public.
    /// let owner_nv_public = NvPublic::builder()
    ///     .with_nv_index(nv_index)
    ///     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    ///     .with_index_attributes(owner_nv_index_attributes)
    ///     .with_data_area_size(32)
    ///     .build()
    ///     .expect("Failed to build NvPublic for owner");
    ///
    /// // Define the NV space.
    /// let owner_nv_index_handle = context
    ///     .nv_define_space(Provision::Owner, None, owner_nv_public)
    ///     .expect("Call to nv_define_space failed");
    ///
    /// # context
    /// #    .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
    /// #    .expect("Call to nv_undefine_space failed");
    /// ```
    pub fn nv_define_space(
        &mut self,
        nv_auth: Provision,
        auth: Option<Auth>,
        public_info: NvPublic,
    ) -> Result<NvIndexHandle> {
        let mut nv_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_DefineSpace(
                    self.mut_context(),
                    AuthHandle::from(nv_auth).into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.unwrap_or_default().into(),
                    &public_info.try_into()?,
                    &mut nv_handle,
                )
            },
            |ret| {
                error!("Error when defining NV space: {:#010X}", ret);
            },
        )?;

        self.handle_manager
            .add_handle(nv_handle.into(), HandleDropAction::Close)?;
        Ok(NvIndexHandle::from(nv_handle))
    }

    /// Deletes an index in the non volatile storage.
    ///
    /// # Details
    /// The method will instruct the TPM to remove a
    /// nv index.
    ///
    /// Please beware that this method requires an authorization
    /// session handle to be present.
    ///
    /// # Arguments
    /// * `nv_auth` - The [Provision] used for authorization.
    /// * `nv_index_handle`- The [NvIndexHandle] associated with
    ///                      the nv area that is to be removed.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::SessionAttributes, constants::SessionType,
    /// #     structures::SymmetricDefinition,
    /// #      handles::NvIndexTpmHandle, attributes::NvIndexAttributes, structures::NvPublic,
    /// #      interface_types::algorithm::HashingAlgorithm,
    /// # };
    /// use tss_esapi::interface_types::resource_handles::Provision;
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let nv_index = NvIndexTpmHandle::new(0x01500023)
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
    /// // Define the NV space.
    /// let owner_nv_index_handle = context
    ///     .nv_define_space(Provision::Owner, None, owner_nv_public)
    ///     .expect("Call to nv_define_space failed");
    ///
    /// context
    ///    .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
    ///    .expect("Call to nv_undefine_space failed");
    /// ```
    pub fn nv_undefine_space(
        &mut self,
        nv_auth: Provision,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_UndefineSpace(
                    self.mut_context(),
                    AuthHandle::from(nv_auth).into(),
                    nv_index_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error when undefining NV space: {:#010X}", ret);
            },
        )?;

        self.handle_manager.set_as_closed(nv_index_handle.into())
    }

    // Missing function: UndefineSpaceSpecial

    /// Reads the public part of an nv index.
    ///
    /// # Details
    /// This method is used to read the public
    /// area and name of a nv index.
    ///
    /// # Arguments
    /// * `nv_index_handle` - The [NvIndexHandle] associated with NV memory
    ///                       for which the public part is to be read.
    /// # Returns
    /// A tuple containing the public area and the name of an nv index.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     handles::NvIndexTpmHandle, interface_types::algorithm::HashingAlgorithm,
    /// #     structures::{SymmetricDefinition, NvPublic}, constants::SessionType,
    /// # };
    /// use tss_esapi::{
    ///       interface_types::resource_handles::Provision,
    /// };
    ///
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500024)
    /// #     .expect("Failed to create NV index tpm handle");
    /// #
    /// # // Create NV index attributes
    /// # let owner_nv_index_attributes = NvIndexAttributes::builder()
    /// #     .with_owner_write(true)
    /// #     .with_owner_read(true)
    /// #     .build()
    /// #     .expect("Failed to create owner nv index attributes");
    /// #
    /// // Create owner nv public.
    /// let owner_nv_public = NvPublic::builder()
    ///     .with_nv_index(nv_index)
    ///     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    ///     .with_index_attributes(owner_nv_index_attributes)
    ///     .with_data_area_size(32)
    ///     .build()
    ///     .expect("Failed to build NvPublic for owner");
    ///
    /// let nv_index_handle = context
    ///    .nv_define_space(Provision::Owner, None, owner_nv_public.clone())
    ///    .expect("Call to nv_define_space failed");
    ///
    /// // Holds the result in order to ensure that the
    /// // NV space gets undefined.
    /// let nv_read_public_result = context.nv_read_public(nv_index_handle);
    ///
    /// context
    ///     .nv_undefine_space(Provision::Owner, nv_index_handle)
    ///     .expect("Call to nv_undefine_space failed");
    ///
    /// // Process result
    /// let (read_nv_public, _name) = nv_read_public_result
    ///     .expect("Call to nv_read_public failed");
    ///
    /// assert_eq!(owner_nv_public, read_nv_public);
    /// ```
    pub fn nv_read_public(&mut self, nv_index_handle: NvIndexHandle) -> Result<(NvPublic, Name)> {
        let mut nv_public_ptr = null_mut();
        let mut nv_name_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_ReadPublic(
                    self.mut_context(),
                    nv_index_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut nv_public_ptr,
                    &mut nv_name_ptr,
                )
            },
            |ret| {
                error!("Error when reading NV public: {:#010X}", ret);
            },
        )?;

        Ok((
            NvPublic::try_from(Context::ffi_data_to_owned(nv_public_ptr))?,
            Name::try_from(Context::ffi_data_to_owned(nv_name_ptr))?,
        ))
    }

    /// Writes data to the NV memory associated with a nv index.
    ///
    /// # Details
    /// This method is used to write a value to
    /// the nv memory in the TPM.
    ///
    /// Please beware that this method requires an authorization
    /// session handle to be present.
    ///
    /// # Arguments
    /// * `auth_handle` - Handle indicating the source of authorization value.
    /// * `nv_index_handle` - The [NvIndexHandle] associated with NV memory
    ///                       where data is to be written.
    /// * `data` - The data, in the form of a [MaxNvBuffer], that is to be written.
    /// * `offset` - The octet offset into the NV area.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     handles::NvIndexTpmHandle, interface_types::algorithm::HashingAlgorithm,
    /// #     structures::{SymmetricDefinition, NvPublic}, constants::SessionType,
    /// # };
    /// use tss_esapi::{
    ///       interface_types::resource_handles::{Provision, NvAuth}, structures::MaxNvBuffer,
    /// };
    /// use std::convert::TryFrom;
    ///
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500025)
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
    ///
    /// let data = MaxNvBuffer::try_from(vec![1, 2, 3, 4, 5, 6, 7])
    ///    .expect("Failed to create MaxNvBuffer from vec");
    ///
    /// let nv_index_handle = context
    ///    .nv_define_space(Provision::Owner, None, owner_nv_public.clone())
    ///    .expect("Call to nv_define_space failed");
    ///
    /// // Use owner authorization
    /// let nv_write_result = context.nv_write(NvAuth::Owner, nv_index_handle, data, 0);
    ///
    /// context
    ///     .nv_undefine_space(Provision::Owner, nv_index_handle)
    ///     .expect("Call to nv_undefine_space failed");
    ///
    /// // Process result
    /// nv_write_result.expect("Call to nv_write failed");
    /// ```
    pub fn nv_write(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
        data: MaxNvBuffer,
        offset: u16,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_Write(
                    self.mut_context(),
                    AuthHandle::from(auth_handle).into(),
                    nv_index_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &data.into(),
                    offset,
                )
            },
            |ret| {
                error!("Error when writing NV: {:#010X}", ret);
            },
        )
    }

    /// Increment monotonic counter index
    ///
    /// # Details
    /// This method is used to increment monotonic counter
    /// in the TPM.
    ///
    /// Please beware that this method requires an authorization
    /// session handle to be present.
    ///
    /// # Arguments
    /// * `auth_handle` - Handle indicating the source of authorization value.
    /// * `nv_index_handle` - The [NvIndexHandle] associated with NV memory
    ///                       where data is to be written.
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     handles::NvIndexTpmHandle, interface_types::algorithm::HashingAlgorithm,
    /// #     structures::{SymmetricDefinition, NvPublic}, constants::SessionType,
    /// #     constants::nv_index_type::NvIndexType,
    /// # };
    /// use tss_esapi::{
    ///       interface_types::resource_handles::{Provision, NvAuth}
    /// };
    ///
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500026)
    /// #     .expect("Failed to create NV index tpm handle");
    /// #
    /// # // Create NV index attributes
    /// # let owner_nv_index_attributes = NvIndexAttributes::builder()
    /// #     .with_owner_write(true)
    /// #     .with_owner_read(true)
    /// #     .with_nv_index_type(NvIndexType::Counter)
    /// #     .build()
    /// #     .expect("Failed to create owner nv index attributes");
    /// #
    /// # // Create owner nv public.
    /// # let owner_nv_public = NvPublic::builder()
    /// #     .with_nv_index(nv_index)
    /// #     .with_index_name_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_index_attributes(owner_nv_index_attributes)
    /// #     .with_data_area_size(8)
    /// #     .build()
    /// #     .expect("Failed to build NvPublic for owner");
    /// #
    /// let nv_index_handle = context
    ///     .nv_define_space(Provision::Owner, None, owner_nv_public.clone())
    ///     .expect("Call to nv_define_space failed");
    ///
    /// let nv_increment_result = context.nv_increment(NvAuth::Owner, nv_index_handle);
    ///
    /// context
    ///     .nv_undefine_space(Provision::Owner, nv_index_handle)
    ///     .expect("Call to nv_undefine_space failed");
    ///
    /// // Process result
    /// nv_increment_result.expect("Call to nv_increment failed");
    /// ```
    pub fn nv_increment(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_Increment(
                    self.mut_context(),
                    AuthHandle::from(auth_handle).into(),
                    nv_index_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| error!("Error when incrementing NV: {:#010X}", ret),
        )
    }

    // Missing function: NV_Extend
    // Missing function: NV_SetBits
    // Missing function: NV_WriteLock
    // Missing function: NV_GlobalWriteLock

    /// Reads data from the nv index.
    ///
    /// # Details
    /// This method is used to read a value from an area in
    /// NV memory of the TPM.
    ///
    /// Please beware that this method requires an authorization
    /// session handle to be present.
    ///
    /// # Arguments
    /// * `auth_handle` - Handle indicating the source of authorization value.
    /// * `nv_index_handle` - The [NvIndexHandle] associated with NV memory
    ///                       where data is to be written.
    /// * `size` -  The number of octets to read.
    /// * `offset`- Octet offset into the NV area.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf, attributes::{SessionAttributes, NvIndexAttributes},
    /// #     handles::NvIndexTpmHandle, interface_types::algorithm::HashingAlgorithm,
    /// #     structures::{SymmetricDefinition, NvPublic}, constants::SessionType,
    /// # };
    /// use tss_esapi::{
    ///       interface_types::resource_handles::{Provision, NvAuth}, structures::MaxNvBuffer,
    /// };
    /// use std::convert::TryFrom;
    ///
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500027)
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
    /// let data = MaxNvBuffer::try_from(vec![1, 2, 3, 4, 5, 6, 7])
    ///    .expect("Failed to create MaxNvBuffer from vec");
    ///
    /// let nv_index_handle = context
    ///    .nv_define_space(Provision::Owner, None, owner_nv_public)
    ///    .expect("Call to nv_define_space failed");
    ///
    /// // Write data using owner authorization
    /// let nv_write_result = context.nv_write(NvAuth::Owner, nv_index_handle, data.clone(), 0);
    ///
    /// // Read data using owner authorization
    /// let data_len = u16::try_from(data.len()).expect("Failed to retrieve length of data");
    /// let nv_read_result = context
    ///     .nv_read(NvAuth::Owner, nv_index_handle, data_len, 0);
    ///
    /// context
    ///     .nv_undefine_space(Provision::Owner, nv_index_handle)
    ///     .expect("Call to nv_undefine_space failed");
    ///
    /// // Process result
    /// nv_write_result.expect("Call to nv_write failed");
    /// let read_data = nv_read_result.expect("Call to nv_read failed");
    /// assert_eq!(data, read_data);
    /// ```
    pub fn nv_read(
        &mut self,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
        size: u16,
        offset: u16,
    ) -> Result<MaxNvBuffer> {
        let mut data_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_NV_Read(
                    self.mut_context(),
                    AuthHandle::from(auth_handle).into(),
                    nv_index_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    size,
                    offset,
                    &mut data_ptr,
                )
            },
            |ret| {
                error!("Error when reading NV: {:#010X}", ret);
            },
        )?;
        MaxNvBuffer::try_from(Context::ffi_data_to_owned(data_ptr))
    }

    // Missing function: NV_ReadLock
    // Missing function: NV_ChangeAuth
    // Missing function: NV_Certify
}
