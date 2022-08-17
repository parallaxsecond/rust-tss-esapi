// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::traits::InPlaceFfiDataZeroizer;
use mbox::MBox;
use std::ops::DerefMut;

/// Function for taking ownership of data that has been
/// allocated with C memory allocation functions in TSS while also
/// zeroizing the memory before freeing it.
#[allow(dead_code)]
pub(crate) fn to_owned_with_zeroized_source<T, U>(data_ptr: *mut T) -> T
where
    T: Copy,
    U: InPlaceFfiDataZeroizer<T>,
{
    let mut ffi_data = unsafe { MBox::from_raw(data_ptr) };
    let owned_ffi_data: T = *ffi_data;
    U::zeroize_ffi_data_in_place(ffi_data.deref_mut());
    owned_ffi_data
}
