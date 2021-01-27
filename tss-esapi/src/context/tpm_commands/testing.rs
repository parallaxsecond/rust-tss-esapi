use crate::{
    structures::MaxBuffer,
    tss2_esys::{Esys_GetTestResult, Esys_SelfTest},
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::TryFrom;
use std::ptr::null_mut;

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

    /// Get the TPM self test result
    ///
    /// The returned buffer data is manufacturer-specific information.
    pub fn get_test_result(&mut self) -> Result<(MaxBuffer, Result<()>)> {
        let mut out_data = null_mut();
        let mut out_rc: u32 = 0;

        let ret = unsafe {
            Esys_GetTestResult(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &mut out_data,
                &mut out_rc,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_data = unsafe { MBox::from_raw(out_data) };
            let out_data = MaxBuffer::try_from(*out_data)?;
            let out_rc = Error::from_tss_rc(out_rc);
            let out_rc = if out_rc.is_success() {
                Ok(())
            } else {
                Err(out_rc)
            };
            Ok((out_data, out_rc))
        } else {
            error!("Error getting test result: {}", ret);
            Err(ret)
        }
    }
}
