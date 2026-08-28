// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::AuthHandle,
    structures::CommandCodeList,
    tss2_esys::{Esys_PP_Commands, Esys_SetAlgorithmSet},
};
use log::error;

impl Context {
    /// Changes the list of commands that require Physical Presence.
    ///
    /// Commands in `set_list` are added to the Physical Presence list before commands in
    /// `clear_list` are removed from it. The TPM silently discards commands that cannot require
    /// Physical Presence. This command itself always requires Physical Presence in addition to
    /// authorization for the platform hierarchy.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `set_list` - Commands to add to the Physical Presence list.
    /// * `clear_list` - Commands to remove from the Physical Presence list.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to determine which commands require assertion of Physical Presence
    /// > (PP) in addition to platformAuth/platformPolicy.
    ///
    /// # Example
    ///
    /// The empty lists make this invocation a no-op. A platform that does not assert Physical
    /// Presence will reject the command, which the example reports without changing TPM state.
    ///
    /// ```rust
    /// use tss_esapi::{
    ///     Context, TctiNameConf,
    ///     handles::AuthHandle,
    ///     interface_types::session_handles::AuthSession,
    ///     structures::CommandCodeList,
    /// };
    ///
    /// let mut context = Context::new(
    ///     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// )
    /// .expect("Failed to create Context");
    ///
    /// let result = context.execute_with_sessions(
    ///     (Some(AuthSession::Password), None, None),
    ///     |ctx| {
    ///         ctx.pp_commands(
    ///             AuthHandle::Platform,
    ///             CommandCodeList::new(),
    ///             CommandCodeList::new(),
    ///         )
    ///     },
    /// );
    /// ```
    pub fn pp_commands(
        &mut self,
        auth_handle: AuthHandle,
        set_list: CommandCodeList,
        clear_list: CommandCodeList,
    ) -> Result<()> {
        let set_list = set_list.into();
        let clear_list = clear_list.into();

        ReturnCode::ensure_success(
            unsafe {
                Esys_PP_Commands(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &set_list,
                    &clear_list,
                )
            },
            |ret| {
                error!("Error changing Physical Presence commands: {:#010X}", ret);
            },
        )
    }

    /// Selects a vendor-dependent set of algorithms used by the TPM.
    ///
    /// The meaning of `algorithm_set` and the effects of changing it are vendor-dependent. The
    /// change can require a reset and may invalidate persistent state. Consult the TPM vendor's
    /// documentation before invoking this command.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `algorithm_set` - The vendor-defined algorithm-set selector.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command allows the platform to change the set of algorithms that are used by the TPM.
    /// > The algorithmSet setting is a vendor-dependent value.
    ///
    /// # Example
    ///
    /// The example is not run because changing the algorithm set may erase TPM objects, NV state,
    /// or policies, depending on the implementation.
    ///
    /// ```rust,no_run
    /// use tss_esapi::{
    ///     Context, TctiNameConf,
    ///     constants::PropertyTag,
    ///     handles::AuthHandle,
    ///     interface_types::session_handles::AuthSession,
    /// };
    ///
    /// let mut context = Context::new(
    ///     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// )
    /// .expect("Failed to create Context");
    /// let algorithm_set = context
    ///     .get_tpm_property(PropertyTag::AlgorithmSet)
    ///     .expect("Failed to read the algorithm set")
    ///     .expect("The TPM did not report an algorithm set");
    ///
    /// context
    ///     .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
    ///         ctx.set_algorithm_set(AuthHandle::Platform, algorithm_set)
    ///     })
    ///     .expect("Failed to set the algorithm set");
    /// ```
    pub fn set_algorithm_set(&mut self, auth_handle: AuthHandle, algorithm_set: u32) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SetAlgorithmSet(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    algorithm_set,
                )
            },
            |ret| {
                error!("Error setting the algorithm set: {:#010X}", ret);
            },
        )
    }
}
