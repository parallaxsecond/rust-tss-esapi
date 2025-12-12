// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{ObjectHandle, TpmHandle},
    interface_types::{algorithm::HashingAlgorithm, reserved_handles::Hierarchy},
    structures::{Auth, Digest, HashcheckTicket, MaxBuffer},
    tss2_esys::{Esys_HashSequenceStart, Esys_SequenceComplete, Esys_SequenceUpdate},
    Context, Result, ReturnCode,
};
use log::error;
use std::ptr::null_mut;

impl Context {
    // Missing function: HMAC_Start
    // Missing function: MAC_Start

    pub fn hash_sequence_start(
        &mut self,
        hashing_algorithm: HashingAlgorithm,
        auth: Option<Auth>,
    ) -> Result<ObjectHandle> {
        let mut sequence_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_HashSequenceStart(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.unwrap_or_default().into(),
                    hashing_algorithm.into(),
                    &mut sequence_handle,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform hash sequence start operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok(ObjectHandle::from(sequence_handle))
    }

    pub fn sequence_update(
        &mut self,
        sequence_handle: ObjectHandle,
        data: MaxBuffer,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SequenceUpdate(
                    self.mut_context(),
                    sequence_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &data.into(),
                )
            },
            |ret| {
                error!(
                    "Error failed to perform sequence update operation: {:#010X}",
                    ret
                );
            },
        )
    }

    pub fn sequence_complete(
        &mut self,
        sequence_handle: ObjectHandle,
        data: MaxBuffer,
        hierarchy: Hierarchy,
    ) -> Result<(Digest, HashcheckTicket)> {
        let mut out_hash_ptr = null_mut();
        let mut validation_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_SequenceComplete(
                    self.mut_context(),
                    sequence_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &data.into(),
                    if cfg!(hierarchy_is_esys_tr) {
                        ObjectHandle::from(hierarchy).into()
                    } else {
                        TpmHandle::from(hierarchy).into()
                    },
                    &mut out_hash_ptr,
                    &mut validation_ptr,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform sequence complete operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok((
            Digest::try_from(Context::ffi_data_to_owned(out_hash_ptr)?)?,
            HashcheckTicket::try_from(Context::ffi_data_to_owned(validation_ptr)?)?,
        ))
    }

    // Missing function: EventSequenceComplete
}
