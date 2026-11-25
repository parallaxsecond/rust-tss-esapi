// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{Context, Result, ReturnCode, handles::ObjectHandle, tss2_esys::Esys_ACT_SetTimeout};
use log::error;

impl Context {
    /// Set the timeout for an Authenticated Countdown Timer (ACT).
    ///
    /// # Arguments
    ///
    /// * `act_handle` - An [ObjectHandle] of the ACT to set.
    /// * `start_timeout` - The start timeout value in seconds.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to set the time remaining before an
    /// > Authenticated Countdown Timer (ACT) expires.
    ///
    /// # Example
    ///
    /// <!--
    /// This example is marked `no_run` because `TPM2_ACT_SetTimeout` is not
    /// supported by swtpm/libtpms; it requires a TPM that provides ACT support.
    /// -->
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{
    /// #     Context, TctiNameConf,
    /// #     constants::SessionType,
    /// #     attributes::SessionAttributesBuilder,
    /// #     interface_types::algorithm::HashingAlgorithm,
    /// #     structures::SymmetricDefinition,
    /// # };
    /// use tss_esapi::{handles::ObjectHandle, tss2_esys::ESYS_TR_RH_ACT_0};
    /// # // Create context
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Create a session for authorizing the ACT
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
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// // ACT handles are vendor-specific; ACT 0 maps to ESYS_TR_RH_ACT_0.
    /// let act_handle = ObjectHandle::from(ESYS_TR_RH_ACT_0);
    /// // Set the ACT to expire 60 seconds from now.
    /// context.execute_with_session(Some(session), |ctx| {
    ///     ctx.act_set_timeout(act_handle, 60)
    ///         .expect("Call to act_set_timeout failed");
    /// });
    /// ```
    pub fn act_set_timeout(&mut self, act_handle: ObjectHandle, start_timeout: u32) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ACT_SetTimeout(
                    self.mut_context(),
                    act_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    start_timeout,
                )
            },
            |ret| {
                error!("Error setting ACT timeout: {:#010X}", ret);
            },
        )
    }
}
