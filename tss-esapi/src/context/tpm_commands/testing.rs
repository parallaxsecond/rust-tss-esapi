use crate::{tss2_esys::Esys_SelfTest, Context, Error, Result};
use log::error;

impl Context {
    /// Execute the TPM self test and returns the result
    pub fn self_test(&mut self, full_test: bool) -> Result<()> {
        let ret = unsafe {
            Esys_SelfTest(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                if full_test { 1 } else { 0 },
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            Ok(())
        } else {
            error!("Error in self-test: {}", ret);
            Err(ret)
        }
    }

    // Missing function: incremental_self_test
    // Missing function: get_test_result
}
