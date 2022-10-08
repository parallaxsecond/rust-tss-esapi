// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::YesNo,
    structures::MaxBuffer,
    tss2_esys::{Esys_GetTestResult, Esys_SelfTest},
    Context, Result, ReturnCode,
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

    // Missing function: incremental_self_test

    /// Get the TPM self test result
    ///
    /// The returned buffer data is manufacturer-specific information.
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
            MaxBuffer::try_from(Context::ffi_data_to_owned(out_data_ptr))?,
            ReturnCode::ensure_success(test_result, |_| {}),
        ))
    }
}
