// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{AuthHandle, ObjectHandle, SessionHandle},
    interface_types::session_handles::PolicySession,
    structures::{
        AuthTicket, Digest, DigestList, Name, Nonce, PcrSelectionList, Signature, Timeout,
        VerifiedTicket,
    },
    tss2_esys::*,
    Context, Error, Result, WrapperErrorKind as ErrorKind,
};
use log::error;
use mbox::MBox;
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
        let mut out_timeout = null_mut();
        let mut out_policy_ticket = null_mut();
        let expiration = match expiration {
            None => 0,
            Some(val) => match i32::try_from(val.as_secs()) {
                Ok(val) => val,
                Err(_) => return Err(Error::local_error(ErrorKind::InvalidParam)),
            },
        };

        let ret = unsafe {
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
                expiration,
                &signature.try_into()?,
                &mut out_timeout,
                &mut out_policy_ticket,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let out_timeout = unsafe { MBox::from_raw(out_timeout) };
            let out_timeout = Timeout::try_from(*out_timeout)?;
            let out_policy_ticket = unsafe { MBox::from_raw(out_policy_ticket) };
            let out_policy_ticket = AuthTicket::try_from(*out_policy_ticket)?;

            Ok((out_timeout, out_policy_ticket))
        } else {
            error!("Error when sending policy signed: {}", ret);
            Err(ret)
        }
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
        let mut out_timeout = null_mut();
        let mut out_policy_ticket = null_mut();
        let expiration = match expiration {
            None => 0,
            Some(val) => match i32::try_from(val.as_secs()) {
                Ok(val) => val,
                Err(_) => return Err(Error::local_error(ErrorKind::InvalidParam)),
            },
        };

        let ret = unsafe {
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
                expiration,
                &mut out_timeout,
                &mut out_policy_ticket,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let out_timeout = unsafe { MBox::from_raw(out_timeout) };
            let out_timeout = Timeout::try_from(*out_timeout)?;
            let out_policy_ticket = unsafe { MBox::from_raw(out_policy_ticket) };
            let out_policy_ticket = AuthTicket::try_from(*out_policy_ticket)?;

            Ok((out_timeout, out_policy_ticket))
        } else {
            error!("Error when sending policy secret: {}", ret);
            Err(ret)
        }
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
    /// * `hash_list` must be at least 2 and at most 8 elements long
    ///
    /// # Errors
    /// * if the hash list provided is too short or too long, a `WrongParamSize` wrapper error will be returned
    pub fn policy_or(
        &mut self,
        policy_session: PolicySession,
        digest_list: DigestList,
    ) -> Result<()> {
        let digest_list = TPML_DIGEST::try_from(digest_list)?;

        let ret = unsafe {
            Esys_PolicyOR(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &digest_list,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy OR: {}", ret);
            Err(ret)
        }
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
        pcr_policy_digest: &Digest,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyPCR(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &pcr_policy_digest.clone().into(),
                &pcr_selection_list.into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy PCR: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on locality.
    ///
    /// The TPM will ensure that the current policy can only complete in the specified
    /// locality (extended) or any of the specified localities (non-extended).
    pub fn policy_locality(
        &mut self,
        policy_session: PolicySession,
        locality: TPMA_LOCALITY,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyLocality(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                locality,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy locality: {}", ret);
            Err(ret)
        }
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
        code: TPM2_CC,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyCommandCode(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                code,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy command code: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on physical presence.
    ///
    /// The TPM will ensure that the current policy can only complete when physical
    /// presence is asserted. The way this is done is implementation-specific.
    pub fn policy_physical_presence(&mut self, policy_session: PolicySession) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyPhysicalPresence(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy physical presence: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on command parameters.
    ///
    /// The TPM will ensure that the current policy can only be used to authorize
    /// a command where the parameters are hashed into cp_hash_a.
    pub fn policy_cp_hash(
        &mut self,
        policy_session: PolicySession,
        cp_hash_a: &Digest,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyCpHash(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &cp_hash_a.clone().into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy command parameters: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on name hash.
    ///
    /// The TPM will ensure that the current policy can only be used to authorize
    /// a command acting on an object whose name hashes to name_hash.
    pub fn policy_name_hash(
        &mut self,
        policy_session: PolicySession,
        name_hash: &Digest,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyNameHash(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &name_hash.clone().into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy name hash: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on duplication parent's name.
    ///
    /// # Arguments
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `object_name` - The [name][Name] of the object being duplicated.
    /// * `new_parent_name` - The [name][Name] of the new parent.
    /// * `include_object` - Flag indicating if `object_name` will be included in policy
    ///                      calculation.
    ///
    /// # Details
    /// Set `include_object` only when this commend is used in conjunction with
    /// [`policy_authorize`][Context::policy_authorize].
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::convert::{TryFrom, TryInto};
    /// # use tss_esapi::attributes::{ObjectAttributesBuilder, SessionAttributesBuilder};
    /// # use tss_esapi::constants::{tss::TPM2_CC_Duplicate, SessionType};
    /// # use tss_esapi::handles::ObjectHandle;
    /// # use tss_esapi::interface_types::{
    /// #     algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #     key_bits::RsaKeyBits,
    /// #     resource_handles::Hierarchy,
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
    ///     .policy_duplication_select(policy_session, &object_name, &parent_name, false)
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
        object_name: &Name,
        new_parent_name: &Name,
        include_object: bool,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyDuplicationSelect(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                object_name.as_ref(),
                new_parent_name.as_ref(),
                if include_object { 1 } else { 0 },
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy duplication select: {}", ret);
            Err(ret)
        }
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
        approved_policy: &Digest,
        policy_ref: &Nonce,
        key_sign: &Name,
        check_ticket: VerifiedTicket,
    ) -> Result<()> {
        let check_ticket = TPMT_TK_VERIFIED::try_from(check_ticket)?;
        let ret = unsafe {
            Esys_PolicyAuthorize(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &approved_policy.clone().into(),
                &policy_ref.clone().into(),
                key_sign.as_ref(),
                &check_ticket,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy authorize: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on authValue.
    ///
    /// The TPM will ensure that the current policy requires the user to know the authValue
    /// used when creating the object.
    pub fn policy_auth_value(&mut self, policy_session: PolicySession) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyAuthValue(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy auth value: {}", ret);
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on password.
    ///
    /// The TPM will ensure that the current policy requires the user to know the password
    /// used when creating the object.
    pub fn policy_password(&mut self, policy_session: PolicySession) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyPassword(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy password: {}", ret);
            Err(ret)
        }
    }

    /// Function for retriving the current policy digest for
    /// the session.
    pub fn policy_get_digest(&mut self, policy_session: PolicySession) -> Result<Digest> {
        let mut policy_digest_ptr = null_mut();
        let ret = unsafe {
            Esys_PolicyGetDigest(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut policy_digest_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let policy_digest = unsafe { MBox::<TPM2B_DIGEST>::from_raw(policy_digest_ptr) };
            Ok(Digest::try_from(*policy_digest)?)
        } else {
            error!(
                "Error failed to peform policy get digest operation: {}.",
                ret
            );
            Err(ret)
        }
    }

    /// Cause conditional gating of a policy based on NV written state.
    ///
    /// The TPM will ensure that the NV index that is used has a specific written state.
    pub fn policy_nv_written(
        &mut self,
        policy_session: PolicySession,
        written_set: bool,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyNvWritten(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                if written_set { 1 } else { 0 },
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error when computing policy NV written state: {}", ret);
            Err(ret)
        }
    }

    /// Bind policy to a specific creation template.
    ///
    /// # Arguments
    /// * `policy_session` - The [policy session][PolicySession] being extended.
    /// * `template_hash` - The [digest][Digest] to be added to the policy.
    pub fn policy_template(
        &mut self,
        policy_session: PolicySession,
        template_hash: &Digest,
    ) -> Result<()> {
        let ret = unsafe {
            Esys_PolicyTemplate(
                self.mut_context(),
                SessionHandle::from(policy_session).into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &template_hash.clone().into(),
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!(
                "Failed to bind template to a specific creation template: {}",
                ret
            );
            Err(ret)
        }
    }
    // Missing function: PolicyAuthorizeNV
}
