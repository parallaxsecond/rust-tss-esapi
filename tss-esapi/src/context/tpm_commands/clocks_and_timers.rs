// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    constants::ClockAdjust,
    handles::AuthHandle,
    structures::TimeInfo,
    tss2_esys::{Esys_ClockRateAdjust, Esys_ClockSet, Esys_ReadClock},
};
use log::error;
use std::{convert::TryFrom, ptr::null_mut};

impl Context {
    /// Read the current time and clock info.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command returns the current values of Time and Clock.
    ///
    /// # Returns
    ///
    /// A [TimeInfo] structure containing the current time and clock information.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let time_info = context.read_clock().unwrap();
    /// println!("Time: {}", time_info.time());
    /// ```
    pub fn read_clock(&mut self) -> Result<TimeInfo> {
        let mut current_time_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_ReadClock(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut current_time_ptr,
                )
            },
            |ret| {
                error!("Error reading clock: {:#010X}", ret);
            },
        )?;
        TimeInfo::try_from(Context::ffi_data_to_owned(current_time_ptr)?)
    }

    /// Set the clock to a new value.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the authorization (Owner or Platform).
    /// * `new_time` - The new clock setting in milliseconds.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to advance the value of the TPM's Clock. The
    /// > command will fail if newTime is less than the current value of Clock
    /// > or if the new time is greater than 0xFFFF000000000000.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::{handles::AuthHandle, interface_types::session_handles::AuthSession};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let time_info = context.read_clock().unwrap();
    /// let new_time = time_info.clock_info().clock() + 100_000;
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| {
    ///         ctx.clock_set(AuthHandle::Owner, new_time)
    ///     })
    ///     .unwrap();
    /// ```
    pub fn clock_set(&mut self, auth_handle: AuthHandle, new_time: u64) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ClockSet(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    new_time,
                )
            },
            |ret| {
                error!("Error setting clock: {:#010X}", ret);
            },
        )
    }

    /// Adjust the TPM clock update rate.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the authorization (Owner or Platform).
    /// * `rate_adjust` - The clock update-rate adjustment to apply.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command adjusts the rate of advance of Clock and Time to provide
    /// > a better approximation to real time.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::{
    /// #     constants::ClockAdjust,
    /// #     handles::AuthHandle,
    /// #     interface_types::session_handles::AuthSession,
    /// # };
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// context
    ///     .execute_with_session(Some(AuthSession::Password), |ctx| {
    ///         ctx.clock_rate_adjust(AuthHandle::Owner, ClockAdjust::NoChange)
    ///     })
    ///     .unwrap();
    /// ```
    pub fn clock_rate_adjust(
        &mut self,
        auth_handle: AuthHandle,
        rate_adjust: ClockAdjust,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_ClockRateAdjust(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    rate_adjust.into(),
                )
            },
            |ret| {
                error!("Error adjusting clock rate: {:#010X}", ret);
            },
        )
    }
}
