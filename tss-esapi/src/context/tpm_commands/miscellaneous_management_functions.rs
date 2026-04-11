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
    /// Set the list of commands that require Physical Presence for confirmation.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `set_list` - A [CommandCodeList] of command codes to add to the PP list.
    /// * `clear_list` - A [CommandCodeList] of command codes to remove from the PP list.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to determine which commands require assertion
    /// > of Physical Presence (PP) in addition to platformAuth/platformPolicy.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::AuthHandle;
    /// # use tss_esapi::structures::CommandCodeList;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// context.pp_commands(
    ///     AuthHandle::Platform,
    ///     CommandCodeList::new(),
    ///     CommandCodeList::new(),
    /// ).unwrap();
    /// ```
    pub fn pp_commands(
        &mut self,
        auth_handle: AuthHandle,
        set_list: CommandCodeList,
        clear_list: CommandCodeList,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_PP_Commands(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &set_list.into(),
                    &clear_list.into(),
                )
            },
            |ret| {
                error!("Error setting PP commands: {:#010X}", ret);
            },
        )
    }

    /// Set the algorithm set of the TPM.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the platform hierarchy.
    /// * `algorithm_set` - A `u32` identifying the algorithm set.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command allows the platform to change the set of algorithms
    /// > that are used by the TPM. The algorithmSet changes the
    /// > group of algorithms that are used in TPM-dependent operations.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::AuthHandle;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // context.set_algorithm_set(AuthHandle::Platform, 0).unwrap();
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
                error!("Error setting algorithm set: {:#010X}", ret);
            },
        )
    }
}
