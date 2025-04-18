// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::LocalityAttributes,
    constants::CommandCode,
    handles::{AuthHandle, NvIndexHandle, ObjectHandle, SessionHandle},
    interface_types::{reserved_handles::NvAuth, session_handles::PolicySession, YesNo},
    structures::{
        AuthTicket, Digest, DigestList, Name, Nonce, PcrSelectionList, Signature, Timeout,
        VerifiedTicket,
    },
    tss2_esys::{
        Esys_PolicyAuthValue, Esys_PolicyAuthorize, Esys_PolicyAuthorizeNV, Esys_PolicyCommandCode,
        Esys_PolicyCpHash, Esys_PolicyDuplicationSelect, Esys_PolicyGetDigest, Esys_PolicyLocality,
        Esys_PolicyNameHash, Esys_PolicyNvWritten, Esys_PolicyOR, Esys_PolicyPCR,
        Esys_PolicyPassword, Esys_PolicyPhysicalPresence, Esys_PolicySecret, Esys_PolicySigned,
        Esys_PolicyTemplate,
    },
    Context, Error, Result, ReturnCode, WrapperErrorKind as ErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;
use std::time::Duration;

impl Context {
    /// Cause the policy to include a signed authorization
    #[allow(clippy::too_many_arguments)]
    pub fn policy_signed(
        &mut self,
        policy_session: PolicySession,
        auth_object: ObjectHandle,
        nonce_tpm: Nonce,
        cp_hash_a: Digest,
        policy_ref: Nonce,
        expiration: Option<Duration>,
        signature: Signature,
    ) -> Result<(Timeout, AuthTicket)> {
        let mut out_timeout_ptr = null_mut();
        let mut out_policy_ticket_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicySigned(
                    self.mut_context(),
                    auth_object.into(),
                    SessionHandle::from(policy_session).into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &nonce_tpm.into(),
                    &cp_hash_a.into(),
                    &policy_ref.into(),
                    i32::try_from(expiration.map_or(0, |v| v.as_secs())).map_err(|e| {
                        error!("Unable to convert duration to i32: {}", e);
                        Error::local_error(ErrorKind::InvalidParam)
                    })?,
                    &signature.try_into()?,
                    &mut out_timeout_ptr,
                    &mut out_policy_ticket_ptr,
                )
            },
            |ret| {
                error!("Error when sending policy signed: {:#010X}", ret);
            },
        )?;
        Ok((
            Timeout::try_from(Context::ffi_data_to_owned(out_timeout_ptr))?,
            AuthTicket::try_from(Context::ffi_data_to_owned(out_policy_ticket_ptr))?,
        ))
    }

    /// Cause the policy to require a secret in authValue
    pub fn policy_secret(
        &mut self,
        policy_session: PolicySession,
        auth_handle: AuthHandle,
        nonce_tpm: Nonce,
        cp_hash_a: Digest,
        policy_ref: Nonce,
        expiration: Option<Duration>,
    ) -> Result<(Timeout, AuthTicket)> {
        let mut out_timeout_ptr = null_mut();
        let mut out_policy_ticket_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicySecret(
                    self.mut_context(),
                    auth_handle.into(),
                    SessionHandle::from(policy_session).into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &nonce_tpm.into(),
                    &cp_hash_a.into(),
                    &policy_ref.into(),
                    i32::try_from(expiration.map_or(0, |v| v.as_secs())).map_err(|e| {
                        error!("Unable to convert duration to i32: {}", e);
                        Error::local_error(ErrorKind::InvalidParam)
                    })?,
                    &mut out_timeout_ptr,
                    &mut out_policy_ticket_ptr,
                )
            },
            |ret| {
                error!("Error when sending policy secret: {:#010X}", ret);
            },
        )?;
        Ok((
            Timeout::try_from(Context::ffi_data_to_owned(out_timeout_ptr))?,
            AuthTicket::try_from(Context::ffi_data_to_owned(out_policy_ticket_ptr))?,
        ))
    }

    // Missing function: PolicyTicket

    /// Cause conditional gating of a policy based on an OR'd condition.
    ///
    /// The TPM will ensure that the current policy digest equals at least
    /// one of the digests.
    /// If this is the case, the policyDigest of the policy session is replaced
    /// by the value of the different hashes.
    ///
    /// # Constraints
    /// * `digest_list` must be at least 2 and at most 8 elements long
    ///
    /// # Errors
    /// * if the hash list provided is too short or too long, a `WrongParamSize` wrapper error will be returned
    pub fn policy_or(
        &mut self,
        policy_session: PolicySession,
        digest_list: DigestList,
    ) -> Result<()> {
        if digest_list.len() < 2 {
            error!(
                "The digest list only contains {} digests, it must contain at least 2",
                digest_list.len()
            );
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }

        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyOR(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &digest_list.try_into()?,
                )
            },
            |ret| {
                error!("Error when computing policy OR: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on PCR.
    ///
    /// # Details
    /// The TPM will use the hash algorithm of the policy_session
    /// to calculate a digest from the values of the pcr slots
    /// specified in the pcr_selections.
    /// This is then compared to pcr_policy_digest if they match then
    /// the policyDigest of the policy session is extended.
    ///
    /// # Errors
    /// * if the pcr policy digest provided is too long, a `WrongParamSize` wrapper error will be returned
    pub fn policy_pcr(
        &mut self,
        policy_session: PolicySession,
        pcr_policy_digest: Digest,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyPCR(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &pcr_policy_digest.into(),
                    &pcr_selection_list.into(),
                )
            },
            |ret| {
                error!("Error when computing policy PCR: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on locality.
    ///
    /// The TPM will ensure that the current policy can only complete in the specified
    /// locality (extended) or any of the specified localities (non-extended).
    pub fn policy_locality(
        &mut self,
        policy_session: PolicySession,
        locality: LocalityAttributes,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyLocality(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    locality.into(),
                )
            },
            |ret| {
                error!("Error when computing policy locality: {:#010X}", ret);
            },
        )
    }

    // Missing function: PolicyNV
    // Missing function: PolicyCounterTimer

    /// Cause conditional gating of a policy based on command code of authorized command.
    ///
    /// The TPM will ensure that the current policy can only be used to complete the command
    /// indicated by code.
    pub fn policy_command_code(
        &mut self,
        policy_session: PolicySession,
        code: CommandCode,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyCommandCode(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    code.into(),
                )
            },
            |ret| {
                error!("Error when computing policy command code: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on physical presence.
    ///
    /// The TPM will ensure that the current policy can only complete when physical
    /// presence is asserted. The way this is done is implementation-specific.
    pub fn policy_physical_presence(&mut self, policy_session: PolicySession) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyPhysicalPresence(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!(
                    "Error when computing policy physical presence: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Cause conditional gating of a policy based on command parameters.
    ///
    /// The TPM will ensure that the current policy can only be used to authorize
    /// a command where the parameters are hashed into cp_hash_a.
    pub fn policy_cp_hash(
        &mut self,
        policy_session: PolicySession,
        cp_hash_a: Digest,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyCpHash(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &cp_hash_a.into(),
                )
            },
            |ret| {
                error!(
                    "Error when computing policy command parameters: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Cause conditional gating of a policy based on name hash.
    ///
    /// The TPM will ensure that the current policy can only be used to authorize
    /// a command acting on an object whose name hashes to name_hash.
    pub fn policy_name_hash(
        &mut self,
        policy_session: PolicySession,
        name_hash: Digest,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyNameHash(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &name_hash.into(),
                )
            },
            |ret| {
                error!("Error when computing policy name hash: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on duplication parent's name.
    ///
    /// # Arguments
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `object_name` - The [name][Name] of the object being duplicated.
    /// * `new_parent_name` - The [name][Name] of the new parent.
    /// * `include_object` - Flag indicating if `object_name` will be included in policy
    ///   calculation.
    ///
    /// # Details
    /// Set `include_object` only when this command is used in conjunction with
    /// [`policy_authorize`][Context::policy_authorize].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::{TryFrom, TryInto};
    /// # use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    /// # use tss_esapi::constants::{CommandCode, SessionType};
    /// # use tss_esapi::handles::ObjectHandle;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #     key_bits::RsaKeyBits,
    /// #     reserved_handles::Hierarchy,
    /// #     session_handles::PolicySession,
    /// # };
    /// # use tss_esapi::structures::SymmetricDefinition;
    /// # use tss_esapi::structures::{
    /// #     PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder, RsaScheme,
    /// #     RsaExponent, Name,
    /// # };
    /// # use tss_esapi::structures::SymmetricDefinitionObject;
    /// # use tss_esapi::abstraction::cipher::Cipher;
    /// # use tss_esapi::{Context, TctiNameConf};
    /// #
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let trial_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Trial,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributesBuilder::new()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         trial_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(trial_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # let object_name: Name = Vec::<u8>::new().try_into().unwrap();
    /// # let parent_name = object_name.clone();
    /// #
    /// context
    ///     .policy_duplication_select(policy_session, object_name, parent_name, false)
    ///     .expect("Policy command code");
    /// #
    /// # /// Digest of the policy that allows duplication
    /// # let digest = context
    /// #     .policy_get_digest(policy_session)
    /// #     .expect("Could retrieve digest");
    /// ```
    pub fn policy_duplication_select(
        &mut self,
        policy_session: PolicySession,
        object_name: Name,
        new_parent_name: Name,
        include_object: bool,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyDuplicationSelect(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &object_name.into(),
                    &new_parent_name.into(),
                    YesNo::from(include_object).into(),
                )
            },
            |ret| {
                error!(
                    "Error when computing policy duplication select: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Cause conditional gating of a policy based on an authorized policy
    ///
    /// The TPM will ensure that the current policy digest is correctly signed
    /// by the ticket in check_ticket and that check_ticket is signed by the key
    /// named in key_sign.
    /// If this is the case, the policyDigest of the policy session is replaced
    /// by the value of the key_sign and policy_ref values.
    pub fn policy_authorize(
        &mut self,
        policy_session: PolicySession,
        approved_policy: Digest,
        policy_ref: Nonce,
        key_sign: &Name,
        check_ticket: VerifiedTicket,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyAuthorize(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &approved_policy.into(),
                    &policy_ref.into(),
                    key_sign.as_ref(),
                    &check_ticket.try_into()?,
                )
            },
            |ret| {
                error!("Error when computing policy authorize: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on authValue.
    ///
    /// The TPM will ensure that the current policy requires the user to know the authValue
    /// used when creating the object.
    pub fn policy_auth_value(&mut self, policy_session: PolicySession) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyAuthValue(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error when computing policy auth value: {:#010X}", ret);
            },
        )
    }

    /// Cause conditional gating of a policy based on password.
    ///
    /// The TPM will ensure that the current policy requires the user to know the password
    /// used when creating the object.
    pub fn policy_password(&mut self, policy_session: PolicySession) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyPassword(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error when computing policy password: {:#010X}", ret);
            },
        )
    }

    /// Function for retrieving the current policy digest for
    /// the session.
    pub fn policy_get_digest(&mut self, policy_session: PolicySession) -> Result<Digest> {
        let mut policy_digest_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyGetDigest(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut policy_digest_ptr,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform policy get digest operation: {:#010X}.",
                    ret
                );
            },
        )?;

        Digest::try_from(Context::ffi_data_to_owned(policy_digest_ptr))
    }

    /// Cause conditional gating of a policy based on NV written state.
    ///
    /// The TPM will ensure that the NV index that is used has a specific written state.
    pub fn policy_nv_written(
        &mut self,
        policy_session: PolicySession,
        written_set: bool,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyNvWritten(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    written_set.into(),
                )
            },
            |ret| {
                error!(
                    "Error when computing policy NV written state: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Bind policy to a specific creation template.
    ///
    /// # Arguments
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `template_hash` - The [digest][Digest] to be added to the policy.
    pub fn policy_template(
        &mut self,
        policy_session: PolicySession,
        template_hash: Digest,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyTemplate(
                    self.mut_context(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &template_hash.into(),
                )
            },
            |ret| {
                error!(
                    "Failed to bind template to a specific creation template: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Cause conditional gating of a policy based on an authorized policy
    /// stored in non-volatile memory.
    ///
    /// # Arguments
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `auth_handle` - Handle indicating the source of authorization value.
    /// * `nv_index_handle` - The [NvIndexHandle] associated with NV memory
    ///   where the policy is stored.
    ///
    /// # Example
    /// ```rust
    /// # use std::convert::TryFrom;
    /// # use tss_esapi::attributes::{NvIndexAttributes, SessionAttributes};
    /// # use tss_esapi::constants::SessionType;
    /// # use tss_esapi::handles::NvIndexTpmHandle;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::HashingAlgorithm,
    /// #     reserved_handles::{NvAuth, Provision},
    /// #     session_handles::PolicySession,
    /// # };
    /// # use tss_esapi::structures::{NvPublic, SymmetricDefinition};
    /// # use tss_esapi::{Context, TctiNameConf};
    /// #
    /// # let mut context = // ...
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # // Set owner session for NV space definition
    /// # let owner_auth_session = context
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
    /// # context.tr_sess_set_attributes(owner_auth_session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(owner_auth_session), None, None));
    /// #
    /// # let trial_session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Trial,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Start auth session failed")
    /// #     .expect("Start auth session returned a NONE handle");
    /// #
    /// # let (policy_auth_session_attributes, policy_auth_session_attributes_mask) =
    /// #     SessionAttributes::builder()
    /// #         .with_decrypt(true)
    /// #         .with_encrypt(true)
    /// #         .build();
    /// # context
    /// #     .tr_sess_set_attributes(
    /// #         trial_session,
    /// #         policy_auth_session_attributes,
    /// #         policy_auth_session_attributes_mask,
    /// #     )
    /// #     .expect("tr_sess_set_attributes call failed");
    /// #
    /// # let policy_session = PolicySession::try_from(trial_session)
    /// #     .expect("Failed to convert auth session into policy session");
    /// #
    /// # let nv_index = NvIndexTpmHandle::new(0x01500600)
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
    /// let nv_index_handle = context
    ///    .nv_define_space(Provision::Owner, None, owner_nv_public)
    ///    .expect("Call to nv_define_space failed");
    ///
    /// context.policy_authorize_nv(
    ///     policy_session,
    ///     NvAuth::Owner,
    ///     nv_index_handle,
    /// ).expect("failed to extend policy with policy_authorize_nv");;
    /// #
    /// # context
    /// #     .nv_undefine_space(Provision::Owner, nv_index_handle)
    /// #     .expect("Call to nv_undefine_space failed");
    /// ```
    pub fn policy_authorize_nv(
        &mut self,
        policy_session: PolicySession,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexHandle,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PolicyAuthorizeNV(
                    self.mut_context(),
                    AuthHandle::from(auth_handle).into(),
                    nv_index_handle.into(),
                    SessionHandle::from(policy_session).into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error when computing policy authorize NV: {:#010X}", ret);
            },
        )
    }
}
