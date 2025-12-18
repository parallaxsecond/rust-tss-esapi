// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ffi::take_from_esys,
    structures::{CreateKeyResult, CreationData, CreationTicket, Digest, Private, Public},
    tss2_esys::{TPM2B_CREATION_DATA, TPM2B_DIGEST, TPM2B_PRIVATE, TPM2B_PUBLIC, TPMT_TK_CREATION},
    Error, Result,
};
use std::{convert::TryFrom, ops::Drop, ptr::null_mut};

/// Struct that handles the output of the
/// Create Esys_Create command and zeroizes
/// the FFI data.
pub(crate) struct CreateCommandOutputHandler {
    ffi_out_public_ptr: Option<*mut TPM2B_PUBLIC>,
    ffi_out_private_ptr: Option<*mut TPM2B_PRIVATE>,
    ffi_creation_data_ptr: Option<*mut TPM2B_CREATION_DATA>,
    ffi_creation_hash_ptr: Option<*mut TPM2B_DIGEST>,
    ffi_creation_ticket_ptr: Option<*mut TPMT_TK_CREATION>,
}

/// Creates a new CreateCommandOutputHandler
impl CreateCommandOutputHandler {
    pub(crate) fn new() -> Self {
        Self {
            ffi_out_private_ptr: Some(null_mut()),
            ffi_out_public_ptr: Some(null_mut()),
            ffi_creation_data_ptr: Some(null_mut()),
            ffi_creation_hash_ptr: Some(null_mut()),
            ffi_creation_ticket_ptr: Some(null_mut()),
        }
    }

    /// A reference to the where 'outPrivate' output parameter pointer shall be stored.
    pub fn ffi_out_private_ptr(&mut self) -> &mut *mut TPM2B_PRIVATE {
        // The unwrap is will always be Some until its dropped.
        self.ffi_out_private_ptr.as_mut().unwrap()
    }

    /// A reference to the where 'outPublic' output parameter pointer shall be stored.
    pub fn ffi_out_public_ptr(&mut self) -> &mut *mut TPM2B_PUBLIC {
        // The unwrap is will always be Some until its dropped.
        self.ffi_out_public_ptr.as_mut().unwrap()
    }

    /// A reference to the where 'creationData' output parameter pointer shall be stored.
    pub fn ffi_creation_data_ptr(&mut self) -> &mut *mut TPM2B_CREATION_DATA {
        // The unwrap is will always be Some until its dropped.
        self.ffi_creation_data_ptr.as_mut().unwrap()
    }

    /// A reference to the where 'creationHash' output parameter pointer shall be stored.
    pub fn ffi_creation_hash_ptr(&mut self) -> &mut *mut TPM2B_DIGEST {
        // The unwrap is will always be Some until its dropped.
        self.ffi_creation_hash_ptr.as_mut().unwrap()
    }

    /// A reference to the where 'creationTicket' output parameter pointer shall be stored.
    pub fn ffi_creation_ticket_ptr(&mut self) -> &mut *mut TPMT_TK_CREATION {
        // The unwrap is will always be Some until its dropped.
        self.ffi_creation_ticket_ptr.as_mut().unwrap()
    }
}

impl TryFrom<CreateCommandOutputHandler> for CreateKeyResult {
    type Error = Error;

    fn try_from(mut ffi_data_handler: CreateCommandOutputHandler) -> Result<CreateKeyResult> {
        // Take and free with Esys_Free; then null out the handler's fields so Drop (if any)
        // won't free them a second time.
        // Be sure to take ownership of any data that might have been allocated
        // so that it gets properly zeroized.
        let out_private_result = ffi_data_handler
            .ffi_out_private_ptr
            .take()
            .ok_or(Error::local_error(
                crate::WrapperErrorKind::InternalError, // It cannot be None
            ))
            .and_then(|ptr| unsafe { take_from_esys(ptr) })
            .and_then(Private::try_from);

        let out_public_result = ffi_data_handler
            .ffi_out_public_ptr
            .take()
            .ok_or(Error::local_error(
                crate::WrapperErrorKind::InternalError, // It cannot be None
            ))
            .and_then(|ptr| unsafe { take_from_esys(ptr) })
            .and_then(Public::try_from);

        let creation_data_result = ffi_data_handler
            .ffi_creation_data_ptr
            .take()
            .ok_or(Error::local_error(
                crate::WrapperErrorKind::InternalError, // It cannot be None
            ))
            .and_then(|ptr| unsafe { take_from_esys(ptr) })
            .and_then(CreationData::try_from);

        let creation_hash_result = ffi_data_handler
            .ffi_creation_hash_ptr
            .take()
            .ok_or(Error::local_error(
                crate::WrapperErrorKind::InternalError, // It cannot be None
            ))
            .and_then(|ptr| unsafe { take_from_esys(ptr) })
            .and_then(Digest::try_from);

        let creation_ticket_result = ffi_data_handler
            .ffi_creation_ticket_ptr
            .take()
            .ok_or(Error::local_error(
                crate::WrapperErrorKind::InternalError, // It cannot be None
            ))
            .and_then(|ptr| unsafe { take_from_esys(ptr) })
            .and_then(CreationTicket::try_from);

        Ok(CreateKeyResult {
            out_private: out_private_result?,
            out_public: out_public_result?,
            creation_data: creation_data_result?,
            creation_hash: creation_hash_result?,
            creation_ticket: creation_ticket_result?,
        })
    }
}

impl Drop for CreateCommandOutputHandler {
    fn drop(&mut self) {
        // Make sure we do not have anything allocated on the heap if the handler gets dropped.
        let _ = self.ffi_out_private_ptr.take().inspect(|&ptr| {
            let _ = unsafe { take_from_esys(ptr) };
        });

        let _ = self.ffi_out_public_ptr.take().inspect(|&ptr| {
            let _ = unsafe { take_from_esys(ptr) };
        });

        let _ = self.ffi_creation_data_ptr.take().inspect(|&ptr| {
            let _ = unsafe { take_from_esys(ptr) };
        });

        let _ = self.ffi_creation_hash_ptr.take().inspect(|&ptr| {
            let _ = unsafe { take_from_esys(ptr) };
        });

        let _ = self.ffi_creation_ticket_ptr.take().inspect(|&ptr| {
            let _ = unsafe { take_from_esys(ptr) };
        });
    }
}
