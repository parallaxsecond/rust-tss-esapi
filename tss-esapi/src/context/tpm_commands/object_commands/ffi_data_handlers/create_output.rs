// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    structures::{
        CreateKeyResult, CreationData, CreationTicket, Digest, Private, Public, PublicBuffer,
    },
    tss2_esys::{TPM2B_CREATION_DATA, TPM2B_DIGEST, TPM2B_PRIVATE, TPM2B_PUBLIC, TPMT_TK_CREATION},
    Error, Result,
};
use std::convert::TryFrom;
use std::ptr::null_mut;

/// Struct that handles the output of the
/// Create Esys_Create command.
pub(crate) struct CreateOutputHandler {
    ffi_out_public_ptr: *mut TPM2B_PUBLIC,
    ffi_out_private_ptr: *mut TPM2B_PRIVATE,
    ffi_creation_data_ptr: *mut TPM2B_CREATION_DATA,
    ffi_creation_hash_ptr: *mut TPM2B_DIGEST,
    ffi_creation_ticket_ptr: *mut TPMT_TK_CREATION,
}

impl CreateOutputHandler {
    pub(crate) fn new() -> Self {
        Self {
            ffi_out_public_ptr: null_mut(),
            ffi_out_private_ptr: null_mut(),
            ffi_creation_data_ptr: null_mut(),
            ffi_creation_hash_ptr: null_mut(),
            ffi_creation_ticket_ptr: null_mut(),
        }
    }

    pub fn ffi_out_public_ptr(&mut self) -> &mut *mut TPM2B_PUBLIC {
        &mut self.ffi_out_public_ptr
    }

    pub fn ffi_out_private_ptr(&mut self) -> &mut *mut TPM2B_PRIVATE {
        &mut self.ffi_out_private_ptr
    }

    pub fn ffi_creation_data_ptr(&mut self) -> &mut *mut TPM2B_CREATION_DATA {
        &mut self.ffi_creation_data_ptr
    }

    pub fn ffi_creation_hash_ptr(&mut self) -> &mut *mut TPM2B_DIGEST {
        &mut self.ffi_creation_hash_ptr
    }

    pub fn ffi_creation_ticket_ptr(&mut self) -> &mut *mut TPMT_TK_CREATION {
        &mut self.ffi_creation_ticket_ptr
    }
}

impl TryFrom<CreateOutputHandler> for CreateKeyResult {
    type Error = Error;

    fn try_from(ffi_data_handler: CreateOutputHandler) -> Result<CreateKeyResult> {
        let out_private_owned = crate::ffi_data::to_owned_with_zeroized_source::<
            TPM2B_PRIVATE,
            Private,
        >(ffi_data_handler.ffi_out_private_ptr);
        let out_public_owned = crate::ffi_data::to_owned_with_zeroized_source::<
            TPM2B_PUBLIC,
            PublicBuffer,
        >(ffi_data_handler.ffi_out_public_ptr);
        let creation_data_owned = crate::ffi_data::to_owned_with_zeroized_source::<
            TPM2B_CREATION_DATA,
            CreationData,
        >(ffi_data_handler.ffi_creation_data_ptr);
        let creation_hash_owned = crate::ffi_data::to_owned_with_zeroized_source::<
            TPM2B_DIGEST,
            Digest,
        >(ffi_data_handler.ffi_creation_hash_ptr);
        let creation_ticket_owned = crate::ffi_data::to_owned_with_zeroized_source::<
            TPMT_TK_CREATION,
            CreationTicket,
        >(ffi_data_handler.ffi_creation_ticket_ptr);
        Ok(CreateKeyResult {
            out_private: Private::try_from(out_private_owned)?,
            out_public: Public::try_from(out_public_owned)?,
            creation_data: CreationData::try_from(creation_data_owned)?,
            creation_hash: Digest::try_from(creation_hash_owned)?,
            creation_ticket: CreationTicket::try_from(creation_ticket_owned)?,
        })
    }
}
