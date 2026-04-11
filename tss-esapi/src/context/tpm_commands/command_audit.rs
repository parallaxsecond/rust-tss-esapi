// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode, handles::AuthHandle, interface_types::algorithm::HashingAlgorithm,
    structures::CommandCodeList, tss2_esys::Esys_SetCommandCodeAuditStatus,
};
use log::error;

impl Context {
    /// Set the command code audit status.
    ///
    /// # Arguments
    ///
    /// * `auth_handle` - An [AuthHandle] for the authorization (Owner or Platform).
    /// * `audit_algorithm` - The [HashingAlgorithm] for the audit digest.
    /// * `set_list` - A [CommandCodeList] of command codes to add to the audit list.
    /// * `clear_list` - A [CommandCodeList] of command codes to remove from the audit list.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command may be used by the Privacy Administrator or platform
    /// > to change the audit status of a command or to set the hash
    /// > algorithm used for the audit digest.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::AuthHandle;
    /// # use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    /// # use tss_esapi::structures::CommandCodeList;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// context.set_command_code_audit_status(
    ///     AuthHandle::Owner,
    ///     HashingAlgorithm::Sha256,
    ///     CommandCodeList::new(),
    ///     CommandCodeList::new(),
    /// ).unwrap();
    /// ```
    pub fn set_command_code_audit_status(
        &mut self,
        auth_handle: AuthHandle,
        audit_algorithm: HashingAlgorithm,
        set_list: CommandCodeList,
        clear_list: CommandCodeList,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SetCommandCodeAuditStatus(
                    self.mut_context(),
                    auth_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    audit_algorithm.into(),
                    &set_list.into(),
                    &clear_list.into(),
                )
            },
            |ret| {
                error!("Error setting command code audit status: {:#010X}", ret);
            },
        )
    }
}
