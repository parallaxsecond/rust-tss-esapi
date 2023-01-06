// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod data_zeroize;

use crate::ffi::data_zeroize::FfiDataZeroize;
use mbox::MBox;
use std::ops::Deref;

/// Function that takes ownership of data that has been
/// allocated with C memory allocation functions in TSS while also
/// zeroizing the memory before freeing it.
///
/// # Arguments
/// * `ffi_data_ptr` - A pointer to the FFI data.
///
/// # Returns
/// The owned version of the FFI data.
pub(crate) fn to_owned_with_zeroized_source<T>(ffi_data_ptr: *mut T) -> T
where
    T: FfiDataZeroize + Copy,
{
    let mut ffi_data = unsafe { MBox::from_raw(ffi_data_ptr) };
    let owned_ffi_data: T = *ffi_data.deref();
    ffi_data.ffi_data_zeroize();
    owned_ffi_data
}
