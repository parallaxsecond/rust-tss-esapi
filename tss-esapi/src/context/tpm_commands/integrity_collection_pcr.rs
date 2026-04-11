// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::{AuthHandle, PcrHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{Auth, Digest, DigestList, DigestValues, MaxBuffer, PcrSelectionList},
    tss2_esys::{
        Esys_PCR_Allocate, Esys_PCR_Event, Esys_PCR_Extend, Esys_PCR_Read, Esys_PCR_Reset,
        Esys_PCR_SetAuthPolicy, Esys_PCR_SetAuthValue, TPM2B_EVENT,
    },
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Extends a PCR with the specified digests.
    ///
    /// # Arguments
    /// * `pcr_handle`- A [PcrHandle] to the PCR slot that is to be extended.
    /// * `digests` - The [DigestValues] with which the slot shall be extended.
    ///
    /// # Details
    /// This method is used to cause an update to the indicated PCR. The digests param
    /// contains the digests for specific algorithms that are to be used.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf,
    /// #     constants::SessionType,
    /// #     attributes::SessionAttributesBuilder,
    /// #     handles::PcrHandle,
    /// #     structures::{Digest, SymmetricDefinition},
    /// # };
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Create session for a pcr
    /// # let pcr_session = context
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(pcr_session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// #
    /// # let digest_sha1 = Digest::try_from(vec![
    /// #       1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    /// #   ])
    /// #   .expect("Failed to create sha1 Digest from data");
    /// #
    /// # let digest_sha256 = Digest::try_from(vec![
    /// #        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    /// #        24, 25, 26, 27, 28, 29, 30, 31, 32,
    /// #    ]).expect("Failed to create Sha256 Digest from data");
    /// use std::convert::TryFrom;
    /// use tss_esapi::{
    ///     structures::{DigestValues},
    ///     interface_types::algorithm::HashingAlgorithm,
    /// };
    /// // Extend both sha256 and sha1
    /// let mut vals = DigestValues::new();
    /// vals.set(
    ///     HashingAlgorithm::Sha1,
    ///     digest_sha1,
    /// );
    /// vals.set(
    ///     HashingAlgorithm::Sha256,
    ///     digest_sha256,
    /// );
    /// // Use pcr_session for authorization when extending
    /// // PCR 16 with the values for the banks specified in
    /// // vals.
    /// context.execute_with_session(Some(pcr_session), |ctx| {
    ///     ctx.pcr_extend(PcrHandle::Pcr16, vals).expect("Call to pcr_extend failed");
    /// });
    /// ```
    pub fn pcr_extend(&mut self, pcr_handle: PcrHandle, digests: DigestValues) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_Extend(
                    self.mut_context(),
                    pcr_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &digests.try_into()?,
                )
            },
            |ret| {
                error!("Error when extending PCR: {:#010X}", ret);
            },
        )
    }

    /// Cause an event to be recorded in a PCR.
    ///
    /// # Arguments
    ///
    /// * `pcr_handle` - A [PcrHandle] of the PCR slot to extend.
    /// * `event_data` - A [MaxBuffer] containing the event data.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to cause an update to the indicated PCR.
    /// > The data in eventData is hashed using each of the implemented hash algorithms.
    /// > For each PCR bank, pcrHandle is extended with the hash of eventData
    /// > for that bank's algorithm.
    ///
    /// # Returns
    ///
    /// A [DigestValues] containing the digest of the event data for each implemented algorithm.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::PcrHandle;
    /// # use tss_esapi::structures::MaxBuffer;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let data = MaxBuffer::from_bytes(&[1, 2, 3, 4]).unwrap();
    /// let digests = context.pcr_event(PcrHandle::Pcr16, data).unwrap();
    /// ```
    pub fn pcr_event(
        &mut self,
        pcr_handle: PcrHandle,
        event_data: MaxBuffer,
    ) -> Result<DigestValues> {
        let mut digests_ptr = null_mut();
        let event_data_bytes = event_data.as_bytes();
        let mut event = TPM2B_EVENT {
            size: event_data_bytes.len() as u16,
            ..Default::default()
        };
        event.buffer[..event_data_bytes.len()].copy_from_slice(event_data_bytes);
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_Event(
                    self.mut_context(),
                    pcr_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &event,
                    &mut digests_ptr,
                )
            },
            |ret| {
                error!("Error when performing PCR event: {:#010X}", ret);
            },
        )?;
        let digests = Context::ffi_data_to_owned(digests_ptr)?;
        let mut digest_values = DigestValues::new();
        for i in 0..digests.count as usize {
            let tpmt_ha = digests.digests[i];
            let algorithm = HashingAlgorithm::try_from(tpmt_ha.hashAlg)?;
            let digest = match algorithm {
                HashingAlgorithm::Sha1 => Digest::from(unsafe { tpmt_ha.digest.sha1 }),
                HashingAlgorithm::Sha256 => Digest::from(unsafe { tpmt_ha.digest.sha256 }),
                HashingAlgorithm::Sha384 => Digest::from(unsafe { tpmt_ha.digest.sha384 }),
                HashingAlgorithm::Sha512 => Digest::from(unsafe { tpmt_ha.digest.sha512 }),
                HashingAlgorithm::Sm3_256 => Digest::from(unsafe { tpmt_ha.digest.sm3_256 }),
                _ => {
                    return Err(crate::Error::local_error(
                        crate::WrapperErrorKind::WrongValueFromTpm,
                    ));
                }
            };
            digest_values.set(algorithm, digest);
        }
        Ok(digest_values)
    }

    /// Reads the values of a PCR.
    ///
    /// # Arguments
    /// * `pcr_selection_list` - A [PcrSelectionList] that contains pcr slots in
    ///   different banks that is going to be read.
    ///
    /// # Details
    /// The provided [PcrSelectionList] contains the pcr slots in the different
    /// banks that is going to be read. It is possible to select more pcr slots
    /// then what will fit in the returned result so the method returns a [PcrSelectionList]
    /// that indicates what values were read. The values that were read are returned
    /// in a [DigestList].
    ///
    /// # Errors
    /// * Several different errors can occur if conversion of return
    ///   data fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// use tss_esapi::{
    ///     interface_types::algorithm::HashingAlgorithm,
    ///     structures::{PcrSelectionListBuilder, PcrSlot},
    /// };
    /// // Create PCR selection list with slots in a bank
    /// // that is going to be read.
    /// let pcr_selection_list = PcrSelectionListBuilder::new()
    ///     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
    ///     .build()
    ///     .expect("Failed to build PcrSelectionList");
    ///
    /// let (update_counter, read_pcr_list, digest_list) = context.pcr_read(pcr_selection_list)
    ///     .expect("Call to pcr_read failed");
    /// ```
    pub fn pcr_read(
        &mut self,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<(u32, PcrSelectionList, DigestList)> {
        let mut pcr_update_counter: u32 = 0;
        let mut pcr_selection_out_ptr = null_mut();
        let mut pcr_values_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_Read(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &pcr_selection_list.into(),
                    &mut pcr_update_counter,
                    &mut pcr_selection_out_ptr,
                    &mut pcr_values_ptr,
                )
            },
            |ret| {
                error!("Error when reading PCR: {:#010X}", ret);
            },
        )?;

        Ok((
            pcr_update_counter,
            PcrSelectionList::try_from(Context::ffi_data_to_owned(pcr_selection_out_ptr)?)?,
            DigestList::try_from(Context::ffi_data_to_owned(pcr_values_ptr)?)?,
        ))
    }

    /// Allocate PCR banks.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `pcr_allocation` - A [PcrSelectionList] specifying the requested PCR allocation.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to set the desired PCR allocation of PCR and algorithms.
    ///
    /// # Returns
    ///
    /// A tuple of `(bool, u32, u32, u32)` representing:
    /// * `allocation_success` - Whether the allocation was successful.
    /// * `max_pcr` - Maximum number of PCR that may be in a bank.
    /// * `size_needed` - Number of octets required to satisfy the request.
    /// * `size_available` - Number of octets available (maximum size of NV).
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::AuthHandle;
    /// # use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    /// # use tss_esapi::structures::{PcrSelectionListBuilder, PcrSlot};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let pcr_allocation = PcrSelectionListBuilder::new()
    ///     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
    ///     .build()
    ///     .unwrap();
    /// let (success, max_pcr, size_needed, size_available) = context
    ///     .pcr_allocate(AuthHandle::Platform, pcr_allocation)
    ///     .unwrap();
    /// ```
    pub fn pcr_allocate(
        &mut self,
        auth_handle: AuthHandle,
        pcr_allocation: PcrSelectionList,
    ) -> Result<(bool, u32, u32, u32)> {
        let mut allocation_success: u8 = 0;
        let mut max_pcr: u32 = 0;
        let mut size_needed: u32 = 0;
        let mut size_available: u32 = 0;
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_Allocate(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &pcr_allocation.into(),
                    &mut allocation_success,
                    &mut max_pcr,
                    &mut size_needed,
                    &mut size_available,
                )
            },
            |ret| {
                error!("Error when allocating PCR: {:#010X}", ret);
            },
        )?;
        Ok((
            allocation_success != 0,
            max_pcr,
            size_needed,
            size_available,
        ))
    }

    /// Set the authorization policy for a PCR.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `auth_policy` - A [Digest] representing the authorization policy.
    /// * `hash_algorithm` - The [HashingAlgorithm] of the policy.
    /// * `pcr_handle` - A [PcrHandle] of the PCR to set the policy for.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to associate a policy with a PCR or group of PCR.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::{AuthHandle, PcrHandle};
    /// # use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    /// # use tss_esapi::structures::Digest;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// context.pcr_set_auth_policy(
    ///     AuthHandle::Platform,
    ///     Digest::default(),
    ///     HashingAlgorithm::Sha256,
    ///     PcrHandle::Pcr16,
    /// ).unwrap();
    /// ```
    pub fn pcr_set_auth_policy(
        &mut self,
        auth_handle: AuthHandle,
        auth_policy: Digest,
        hash_algorithm: HashingAlgorithm,
        pcr_handle: PcrHandle,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_SetAuthPolicy(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth_policy.into(),
                    hash_algorithm.into(),
                    pcr_handle.into(),
                )
            },
            |ret| {
                error!("Error when setting PCR auth policy: {:#010X}", ret);
            },
        )
    }

    /// Set the authorization value for a PCR.
    ///
    /// # Arguments
    ///
    /// * `pcr_handle` - A [PcrHandle] of the PCR to set the auth value for.
    /// * `auth` - An [Auth] value for the PCR.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command changes the authValue of a PCR or group of PCR.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::PcrHandle;
    /// # use tss_esapi::structures::Auth;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let auth = Auth::from_bytes(&[1, 2, 3, 4]).unwrap();
    /// context.pcr_set_auth_value(PcrHandle::Pcr16, auth).unwrap();
    /// ```
    pub fn pcr_set_auth_value(&mut self, pcr_handle: PcrHandle, auth: Auth) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_SetAuthValue(
                    self.mut_context(),
                    pcr_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.into(),
                )
            },
            |ret| {
                error!("Error when setting PCR auth value: {:#010X}", ret);
            },
        )
    }

    /// Resets the value in a PCR.
    ///
    /// # Arguments
    /// * `pcr_handle` -  A [PcrHandle] to the PCR slot that is to be reset.
    ///
    /// # Details
    /// If the attributes of the PCR indicates that it is allowed
    /// to reset them and the proper authorization is provided then
    /// this method can be used to set the the specified PCR in all
    /// banks to 0.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf,
    /// #     constants::SessionType,
    /// #     attributes::SessionAttributesBuilder,
    /// #     structures::SymmetricDefinition,
    /// #     interface_types::algorithm::HashingAlgorithm,
    /// # };
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Create session for a pcr
    /// # let pcr_session = context
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(pcr_session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    ///
    /// use tss_esapi::{
    ///      handles::PcrHandle
    /// };
    /// context.execute_with_session(Some(pcr_session), |ctx| {
    ///     ctx.pcr_reset(PcrHandle::Pcr16).expect("Call to pcr_reset failed");
    /// });
    /// ```
    pub fn pcr_reset(&mut self, pcr_handle: PcrHandle) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PCR_Reset(
                    self.mut_context(),
                    pcr_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error when resetting PCR: {:#010X}", ret);
            },
        )
    }

    // Missing function: _TPM_Hash_Start (platform-level indication, not an ESAPI command)
    // Missing function: _TPM_Hash_Data (platform-level indication, not an ESAPI command)
    // Missing function: _TPM_Hash_End (platform-level indication, not an ESAPI command)
}
