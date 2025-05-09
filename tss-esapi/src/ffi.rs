// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub mod data_zeroize;

use crate::{ffi::data_zeroize::FfiDataZeroize, Error, Result, WrapperErrorKind};
use log::error;
use malloced::Malloced;
use std::{convert::TryFrom, ops::Deref};

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
    let mut ffi_data = unsafe { Malloced::from_raw(ffi_data_ptr) };
    let owned_ffi_data: T = *ffi_data.deref();
    ffi_data.ffi_data_zeroize();
    owned_ffi_data
}

/// Function that takes ownership of bytes that are stored in a
/// buffer that has been allocated with C memory allocation functions in TSS.
///
/// # Arguments
/// * `ffi_bytes_ptr` - A pointer to the FFI buffer.
/// * `size`          - The number of bytes to read from the buffer.
///
/// # Returns
/// The owned bytes in the form of a `Vec<u8>` object.
pub fn to_owned_bytes(ffi_bytes_ptr: *mut u8, size: usize) -> Vec<u8> {
    let ffi_bytes = unsafe { Malloced::<[u8]>::slice_from_raw_parts(ffi_bytes_ptr, size) };
    Vec::<u8>::from(ffi_bytes.as_ref())
}

/// Type used for handling `size_t` variables
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct FfiSizeType(crate::tss2_esys::size_t);

impl FfiSizeType {
    /// Returns an unsafe mutable pointer to the `size_t` value.
    pub(crate) fn as_mut_ptr(&mut self) -> *mut crate::tss2_esys::size_t {
        &mut self.0
    }
}

impl From<crate::tss2_esys::size_t> for FfiSizeType {
    fn from(value: crate::tss2_esys::size_t) -> Self {
        Self(value)
    }
}

impl From<FfiSizeType> for crate::tss2_esys::size_t {
    fn from(ffi: FfiSizeType) -> crate::tss2_esys::size_t {
        ffi.0
    }
}

impl TryFrom<usize> for FfiSizeType {
    type Error = Error;
    fn try_from(native: usize) -> Result<Self> {
        crate::tss2_esys::size_t::try_from(native)
            .map(FfiSizeType)
            .map_err(|err| {
                error!("Failed to convert `usize` to `size_t`: {}", err);
                Error::local_error(WrapperErrorKind::UnsupportedParam)
            })
    }
}

impl TryFrom<FfiSizeType> for usize {
    type Error = Error;
    fn try_from(ffi: FfiSizeType) -> Result<usize> {
        usize::try_from(ffi.0).map_err(|err| {
            error!("Failed to convert `size_t` to `usize`: {}", err);
            Error::local_error(WrapperErrorKind::UnsupportedParam)
        })
    }
}
