use crate::{
    constants::types::startup::StartupType, tss2_esys::Esys_Startup, Context, Error, Result,
};
use log::error;

impl Context {
    /// Send a TPM2_STARTUP command to the TPM
    pub fn startup(&mut self, startup_type: StartupType) -> Result<()> {
        let ret = unsafe { Esys_Startup(self.mut_context(), startup_type.into()) };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            Ok(())
        } else {
            error!("Error while starting up TPM: {}", ret);
            Err(ret)
        }
    }

    // Missing function: shutdown
}
