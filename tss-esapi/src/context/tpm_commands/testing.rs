// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Error, Result, ReturnCode, WrapperErrorKind,
    constants::AlgorithmIdentifier,
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

    /// Performs incremental self-tests for selected algorithms.
    ///
    /// Algorithms that have already been tested are not tested again. Passing an empty slice does
    /// not start any tests and can be used to query which algorithms remain untested.
    ///
    /// # Arguments
    ///
    /// * `to_test` - Algorithms that the TPM should test in anticipation of future use.
    ///
    /// # Returns
    ///
    /// The algorithms or functions for which some testing remains incomplete. This is not a list
    /// of only the tests scheduled by this call.
    ///
    /// # Errors
    ///
    /// Returns [WrapperErrorKind::WrongParamSize] if `to_test` exceeds the TPM algorithm-list
    /// capacity. Invalid data returned by the TPM is also reported as an error.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command causes the TPM to perform a test of the selected algorithms.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tss_esapi::{Context, TctiNameConf};
    ///
    /// let mut context = Context::new(
    ///     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// )
    /// .expect("Failed to create Context");
    ///
    /// let to_do_list = context
    ///     .incremental_self_test(&[])
    ///     .expect("Failed to query pending self-tests");
    /// println!("{} algorithms still require testing", to_do_list.len());
    /// ```
    pub fn incremental_self_test(
        &mut self,
        to_test: &[AlgorithmIdentifier],
    ) -> Result<Vec<AlgorithmIdentifier>> {
        let mut to_test_list = TPML_ALG::default();
        if to_test.len() > to_test_list.algorithms.len() {
            error!(
                "Too many algorithms requested for incremental self-test ({} > {})",
                to_test.len(),
                to_test_list.algorithms.len()
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }

        to_test_list.count = u32::try_from(to_test.len())
            .map_err(|_| Error::local_error(WrapperErrorKind::WrongParamSize))?;
        for (&algorithm, destination) in to_test.iter().zip(to_test_list.algorithms.iter_mut()) {
            *destination = algorithm.into();
        }

        let mut to_do_list_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_IncrementalSelfTest(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &to_test_list,
                    &mut to_do_list_ptr,
                )
            },
            |ret| {
                error!("Error performing incremental self-test: {:#010X}", ret);
            },
        )?;

        let to_do_list = Context::ffi_data_to_owned(to_do_list_ptr)?;
        let to_do_count = usize::try_from(to_do_list.count).map_err(|_| {
            error!(
                "Invalid algorithm count returned by incremental self-test: {}",
                to_do_list.count
            );
            Error::local_error(WrapperErrorKind::WrongValueFromTpm)
        })?;
        if to_do_count > to_do_list.algorithms.len() {
            error!(
                "Invalid algorithm count returned by incremental self-test ({} > {})",
                to_do_count,
                to_do_list.algorithms.len()
            );
            return Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm));
        }

        to_do_list.algorithms[..to_do_count]
            .iter()
            .copied()
            .map(AlgorithmIdentifier::try_from)
            .collect()
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
    /// or else a `TssError` (see [Error]) is returned.
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
