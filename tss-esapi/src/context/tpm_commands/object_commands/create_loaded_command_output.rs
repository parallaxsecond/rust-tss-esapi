// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    handles::ObjectHandle,
    structures::{CreateLoadedKeyResult, Private, Public},
    tss2_esys::{ESYS_TR, TPM2B_PRIVATE, TPM2B_PUBLIC},
    Error, Result,
};
use std::convert::TryFrom;
use std::ptr::null_mut;

/// Struct that handles the output of the
/// Create Esys_CreateLoaded command and zeroizes
/// the FFI data.
pub(crate) struct CreateLoadedCommandOutputHandler {
    ffi_out_object_handle: ESYS_TR,
    // object
    ffi_out_public_ptr: *mut TPM2B_PUBLIC,
    ffi_out_private_ptr: *mut TPM2B_PRIVATE,
    // name
    // ffi_out_name_ptr: *mut TPM2B_NAME,
}

/// Creates a new CreateLoadedCommandOutputHandler
impl CreateLoadedCommandOutputHandler {
    pub(crate) fn new() -> Self {
        let ffi_out_object_handle = ObjectHandle::None.into();
        Self {
            ffi_out_object_handle,
            ffi_out_public_ptr: null_mut(),
            ffi_out_private_ptr: null_mut(),
            // ffi_out_name_ptr: null_mut(),
        }
    }

    /// A reference to the where 'objectHandle' output parameter pointer shall be stored.
    pub fn ffi_out_object_handle(&mut self) -> &mut ESYS_TR {
        &mut self.ffi_out_object_handle
    }

    /// A reference to the where 'outPrivate' output parameter pointer shall be stored.
    pub fn ffi_out_private_ptr(&mut self) -> &mut *mut TPM2B_PRIVATE {
        &mut self.ffi_out_private_ptr
    }

    /// A reference to the where 'outPublic' output parameter pointer shall be stored.
    pub fn ffi_out_public_ptr(&mut self) -> &mut *mut TPM2B_PUBLIC {
        &mut self.ffi_out_public_ptr
    }

    /*
    /// A reference to the where 'name' output parameter pointer shall be stored.
    pub fn ffi_out_name_ptr(&mut self) -> &mut *mut TPM2B_NAME {
        &mut self.ffi_out_name_ptr
    }
    */
}

impl TryFrom<CreateLoadedCommandOutputHandler> for CreateLoadedKeyResult {
    type Error = Error;

    fn try_from(ffi_data_handler: CreateLoadedCommandOutputHandler) -> Result<CreateLoadedKeyResult> {

        let object_handle = ObjectHandle::from(ffi_data_handler.ffi_out_object_handle);

        let out_private_owned =
            crate::ffi::to_owned_with_zeroized_source(ffi_data_handler.ffi_out_private_ptr);
        let out_public_owned =
            crate::ffi::to_owned_with_zeroized_source(ffi_data_handler.ffi_out_public_ptr);

        // let out_name_owned =
        //     crate::ffi::to_owned_with_zeroized_source(ffi_data_handler.ffi_out_name_ptr);

        Ok(CreateLoadedKeyResult {
            object_handle,
            out_private: Private::try_from(out_private_owned)?,
            out_public: Public::try_from(out_public_owned)?,
            // out_name: Name::try_from(out_name_owned)?,
        })
    }
}
