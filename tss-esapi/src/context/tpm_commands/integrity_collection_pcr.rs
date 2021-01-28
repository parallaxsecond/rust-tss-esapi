use crate::{
    handles::PcrHandle,
    structures::{DigestValues, PcrSelectionList},
    tss2_esys::*,
    utils::PcrData,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
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
    /// #     Context, Tcti,
    /// #     constants::{
    /// #         algorithm::Cipher,
    /// #         types::session::SessionType,
    /// #     },
    /// #     session::SessionAttributesBuilder,
    /// #     handles::PcrHandle,
    /// #     structures::Digest,
    /// # };
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// # // Create session for a pcr
    /// # let pcr_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         Cipher::aes_256_cfb(),
    /// #         tss_esapi::constants::algorithm::HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Recived invalid handle");
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
    ///     constants::algorithm::HashingAlgorithm,
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
        let ret = unsafe {
            Esys_PCR_Extend(
                self.mut_context(),
                pcr_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &digests.try_into()?,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when extending PCR: {}", ret);
            Err(ret)
        }
    }

    // Missing function: PCR_Event

    /// Reads the values of a PCR.
    ///
    /// # Arguments
    /// * `pcr_selection_list` - A [PcrSelectionList] that contains pcr slots in
    /// different banks that is going to be read.
    ///
    /// # Details
    /// The provided [PcrSelectionList] contains the pcr slots in the different
    /// banks that is going to be read. It is possible to select more pcr slots
    /// then what will fit in the returned result so the method returns a [PcrSelectionList]
    /// that indicates what values that was read. The values that was read are returned
    /// in the [PcrData].
    ///
    /// # Errors
    /// * Several different errors can occur if conversion of return
    ///   data fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, Tcti};
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// use tss_esapi::{
    ///     constants::algorithm::HashingAlgorithm,
    ///     structures::{PcrSelectionListBuilder, PcrSlot},
    /// };
    /// // Create PCR selection list with slots in a bank
    /// // that is going to be read.
    /// let pcr_selection_list = PcrSelectionListBuilder::new()
    ///     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1])
    ///     .build();
    ///
    /// let (update_counter, read_pcr_list, pcr_data) = context.pcr_read(&pcr_selection_list)
    ///     .expect("Call to pcr_read failed");
    /// ```
    pub fn pcr_read(
        &mut self,
        pcr_selection_list: &PcrSelectionList,
    ) -> Result<(u32, PcrSelectionList, PcrData)> {
        let mut pcr_update_counter: u32 = 0;
        let mut tss_pcr_selection_list_out_ptr = null_mut();
        let mut tss_digest_ptr = null_mut();
        let ret = unsafe {
            Esys_PCR_Read(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &pcr_selection_list.clone().into(),
                &mut pcr_update_counter,
                &mut tss_pcr_selection_list_out_ptr,
                &mut tss_digest_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let tss_pcr_selection_list_out =
                unsafe { MBox::<TPML_PCR_SELECTION>::from_raw(tss_pcr_selection_list_out_ptr) };
            let tss_digest = unsafe { MBox::<TPML_DIGEST>::from_raw(tss_digest_ptr) };
            Ok((
                pcr_update_counter,
                PcrSelectionList::try_from(*tss_pcr_selection_list_out)?,
                PcrData::new(tss_pcr_selection_list_out.as_ref(), tss_digest.as_ref())?,
            ))
        } else {
            error!("Error when reading PCR: {}", ret);
            Err(ret)
        }
    }

    // Missing function: PCR_Allocate
    // Missing function: PCR_SetAuthPolicy
    // Missing function: PCR_SetAuthValue

    /// Resets the value in a PCR.
    ///
    /// # Arguments
    /// * `pcr_handle` -  A [PcrHandle] to the PCR slot that is to be resetted.
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
    /// #     Context, Tcti,
    /// #     constants::{
    /// #         algorithm::{HashingAlgorithm, Cipher},
    /// #         types::session::SessionType,
    /// #     },
    /// #     session::SessionAttributesBuilder,
    /// # };
    /// # use std::{env, str::FromStr};
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// # // Create session for a pcr
    /// # let pcr_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         Cipher::aes_256_cfb(),
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Recived invalid handle");
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
        let ret = unsafe {
            Esys_PCR_Reset(
                self.mut_context(),
                pcr_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when resetting PCR: {}", ret);
            Err(ret)
        }
    }

    // Missing function: _TPM_Hash_Start
    // Missing function: _TPM_Hash_Data
    // Missing function: _TPM_Hash_End
}
