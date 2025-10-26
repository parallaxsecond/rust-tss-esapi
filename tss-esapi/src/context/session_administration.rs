// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::{SessionAttributes, SessionAttributesMask},
    ffi::take_from_esys,
    handles::SessionHandle,
    interface_types::session_handles::AuthSession,
    structures::Nonce,
    tss2_esys::{Esys_TRSess_GetAttributes, Esys_TRSess_GetNonceTPM, Esys_TRSess_SetAttributes},
    Context, Result, ReturnCode,
};
use log::error;
use std::convert::TryInto;

impl Context {
    /// Set the given attributes on a given session.
    pub fn tr_sess_set_attributes(
        &mut self,
        session: AuthSession,
        attributes: SessionAttributes,
        mask: SessionAttributesMask,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_TRSess_SetAttributes(
                    self.mut_context(),
                    SessionHandle::from(session).into(),
                    attributes.try_into()?,
                    mask.try_into()?,
                )
            },
            |ret| {
                error!("Error when setting session attributes: {:#010X}", ret);
            },
        )
    }

    /// Get session attribute flags.
    pub fn tr_sess_get_attributes(&mut self, session: AuthSession) -> Result<SessionAttributes> {
        let mut flags = 0;
        ReturnCode::ensure_success(
            unsafe {
                Esys_TRSess_GetAttributes(
                    self.mut_context(),
                    SessionHandle::from(session).into(),
                    &mut flags,
                )
            },
            |ret| {
                error!("Error when getting session attributes: {:#010X}", ret);
            },
        )?;
        Ok(SessionAttributes(flags))
    }

    /// Get the TPM nonce from a session.
    ///
    /// # Arguments
    /// * `session` - An [AuthSession] handle to the authentication session from which to retrieve
    ///   the TPM nonce.
    ///
    /// # Returns
    /// The TPM nonce as a [Nonce] struct on success.
    ///
    /// # Details
    /// This function retrieves the nonceTPM value from an authentication session.
    ///
    /// Extracted nonceTPM can be useful in some scenarios. For example, a TPM object protected by a
    /// PolicySigned policy requires the nonceTPM value to be extracted and included in the signed
    /// digest to satisfy the policy.
    ///
    /// # Example
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::constants::SessionType;
    /// # use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    /// # use tss_esapi::structures::SymmetricDefinition;
    ///
    /// let mut context = Context::new(
    ///     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// ).expect("Failed to create context");
    ///
    /// let session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Policy,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Failed to create session")
    ///     .expect("Received invalid handle");
    /// let nonce_tpm = context.tr_sess_get_nonce_tpm(session).expect("Failed to get nonceTPM");
    /// // Use the nonce_tpm value as needed
    /// ```
    pub fn tr_sess_get_nonce_tpm(&mut self, session: AuthSession) -> Result<Nonce> {
        let mut nonce_ptr = std::ptr::null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_TRSess_GetNonceTPM(
                    self.mut_context(),
                    SessionHandle::from(session).into(),
                    &mut nonce_ptr,
                )
            },
            |ret| {
                error!("Error when getting session nonceTPM: {:#010X}", ret);
            },
        )?;

        let nonce_tpm = unsafe { take_from_esys(nonce_ptr)? };
        nonce_tpm.try_into()
    }
}
