// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Error, Result, ReturnCode, WrapperErrorKind,
    interface_types::YesNo,
    structures::MaxBuffer,
    tss2_esys::{Esys_GetTestResult, Esys_IncrementalSelfTest, Esys_SelfTest, TPML_ALG},
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Execute the TPM self test and returns the result
    pub fn self_test(&mut self, full_test: bool) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SelfTest(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    YesNo::from(full_test).into(),
                )
            },
            |ret| {
                error!("Error in self-test: {:#010X}", ret);
            },
        )
    }

    /// Run an incremental self test on the selected algorithms.
    ///
    /// # Arguments
    ///
    /// * `to_test` - A list of algorithm IDs to test.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command causes the TPM to perform a test of the selected algorithms.
    ///
    /// # Returns
    ///
    /// A list of algorithm IDs that still need to be tested.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let to_do_list = context.incremental_self_test(&[]).unwrap();
    /// ```
    pub fn incremental_self_test(&mut self, to_test: &[u16]) -> Result<Vec<u16>> {
        let mut tpml_alg = TPML_ALG {
            count: to_test.len() as u32,
            ..Default::default()
        };
        if to_test.len() > tpml_alg.algorithms.len() {
            error!(
                "Too many algorithms to test ({}), maximum is {}",
                to_test.len(),
                tpml_alg.algorithms.len()
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        tpml_alg.algorithms[..to_test.len()].copy_from_slice(to_test);

        let mut to_do_list_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_IncrementalSelfTest(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &tpml_alg,
                    &mut to_do_list_ptr,
                )
            },
            |ret| {
                error!("Error in incremental self test: {:#010X}", ret);
            },
        )?;
        let to_do_list = Context::ffi_data_to_owned(to_do_list_ptr)?;
        Ok(to_do_list.algorithms[..to_do_list.count as usize].to_vec())
    }

    /// Get the TPM self test result
    ///
    /// # Details
    /// The first parameter returned is a buffer with manufacturer-specific information.
    ///
    /// The second parameter returned by the method is an indicator of how the
    /// test went in the form a [Result].
    ///
    /// If testing of all functions is complete without functional failures then Ok(())
    /// or else a `TssError` (see [Error](crate::error::Error)) is returned.
    ///
    /// - A [TpmFormatZeroWarningResponseCode](crate::error::TpmFormatZeroWarningResponseCode) with a `Testing`
    ///   [TpmFormatZeroWarning](crate::constants::return_code::TpmFormatZeroWarning) indicates that the test
    ///   are not complete.
    ///
    /// - A [TpmFormatZeroErrorResponseCode](crate::error::TpmFormatZeroErrorResponseCode) with a `NeedsTest`
    ///   [TpmFormatZeroError](crate::constants::return_code::TpmFormatZeroError) indicates that no self test
    ///   has been performed and testable function has not been tested.
    ///
    /// - A [TpmFormatZeroErrorResponseCode](crate::error::TpmFormatZeroErrorResponseCode) with a `Failure`
    ///   [TpmFormatZeroError](crate::constants::return_code::TpmFormatZeroError) indicates that there was
    ///   a failure.
    ///
    /// See [Part 3, Commands](https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf).
    pub fn get_test_result(&mut self) -> Result<(MaxBuffer, Result<()>)> {
        let mut out_data_ptr = null_mut();
        let mut test_result: u32 = 0;

        ReturnCode::ensure_success(
            unsafe {
                Esys_GetTestResult(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &mut out_data_ptr,
                    &mut test_result,
                )
            },
            |ret| {
                error!("Error getting test result: {:#010X}", ret);
            },
        )?;
        Ok((
            MaxBuffer::try_from(Context::ffi_data_to_owned(out_data_ptr)?)?,
            ReturnCode::ensure_success(test_result, |_| {}),
        ))
    }
}
