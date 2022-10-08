// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::{Digest, SensitiveData},
    tss2_esys::{Esys_GetRandom, Esys_StirRandom},
    Context, Error, Result, ReturnCode, WrapperErrorKind as ErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Get a number of random bytes from the TPM and return them.
    ///
    /// # Errors
    /// * if converting `num_bytes` to `u16` fails, a `WrongParamSize` will be returned
    pub fn get_random(&mut self, num_bytes: usize) -> Result<Digest> {
        let mut random_bytes_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_GetRandom(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    num_bytes
                        .try_into()
                        .map_err(|_| Error::local_error(ErrorKind::WrongParamSize))?,
                    &mut random_bytes_ptr,
                )
            },
            |ret| {
                error!("Error in getting random bytes: {:#010X}", ret);
            },
        )?;
        Digest::try_from(Context::ffi_data_to_owned(random_bytes_ptr))
    }

    /// Add additional information into the TPM RNG state
    pub fn stir_random(&mut self, in_data: SensitiveData) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_StirRandom(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &in_data.into(),
                )
            },
            |ret| {
                error!("Error stirring random: {:#010X}", ret);
            },
        )
    }
}
