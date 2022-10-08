// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::StartupType,
    tss2_esys::{Esys_Shutdown, Esys_Startup},
    Context, Result, ReturnCode,
};
use log::error;

impl Context {
    /// Send a TPM2_STARTUP command to the TPM
    pub fn startup(&mut self, startup_type: StartupType) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe { Esys_Startup(self.mut_context(), startup_type.into()) },
            |ret| {
                error!("Error while starting up TPM: {:#010X}", ret);
            },
        )
    }

    /// Send a TPM2_SHUTDOWN command to the TPM
    pub fn shutdown(&mut self, shutdown_type: StartupType) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_Shutdown(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    shutdown_type.into(),
                )
            },
            |ret| {
                error!("Error while shutting down TPM: {:#010X}", ret);
            },
        )
    }
}
