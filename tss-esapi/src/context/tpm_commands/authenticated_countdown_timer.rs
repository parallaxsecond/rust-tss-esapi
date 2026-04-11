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
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // ACT handles are vendor-specific
    /// # // context.act_set_timeout(act_handle, 60).unwrap();
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
