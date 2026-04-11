// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::AuthHandle,
    tss2_esys::{Esys_DictionaryAttackLockReset, Esys_DictionaryAttackParameters},
};
use log::error;

impl Context {
    /// Reset the dictionary attack lockout.
    ///
    /// # Arguments
    ///
    /// * `lock_handle` - An [AuthHandle] referencing the lockout authorization.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command cancels the effect of a TPM lockout due to a number of successive
    /// > authorization failures. If this command is properly authorized, the lockout counter
    /// > is set to zero.
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
    /// context.dictionary_attack_lock_reset(AuthHandle::Lockout).unwrap();
    /// ```
    pub fn dictionary_attack_lock_reset(&mut self, lock_handle: AuthHandle) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_DictionaryAttackLockReset(
                    self.mut_context(),
                    lock_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                )
            },
            |ret| {
                error!("Error resetting dictionary attack lockout: {:#010X}", ret);
            },
        )
    }

    /// Set the dictionary attack parameters.
    ///
    /// # Arguments
    ///
    /// * `lock_handle` - An [AuthHandle] referencing the lockout authorization.
    /// * `new_max_tries` - Count of authorization failures before the lockout is imposed.
    /// * `new_recovery_time` - Time in seconds before the authorization failure count is
    ///   automatically decremented.
    /// * `lockout_recovery` - Time in seconds after a lockoutAuth failure before use of
    ///   lockoutAuth may be attempted.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command changes the lockout parameters.
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
    /// context.dictionary_attack_parameters(AuthHandle::Lockout, 10, 300, 300).unwrap();
    /// ```
    pub fn dictionary_attack_parameters(
        &mut self,
        lock_handle: AuthHandle,
        new_max_tries: u32,
        new_recovery_time: u32,
        lockout_recovery: u32,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_DictionaryAttackParameters(
                    self.mut_context(),
                    lock_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    new_max_tries,
                    new_recovery_time,
                    lockout_recovery,
                )
            },
            |ret| {
                error!("Error setting dictionary attack parameters: {:#010X}", ret);
            },
        )
    }
}
