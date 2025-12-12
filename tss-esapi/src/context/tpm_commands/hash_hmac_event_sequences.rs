// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::ObjectHandle,
    interface_types::algorithm::HashingAlgorithm,
    structures::{Auth, MaxBuffer},
    tss2_esys::{Esys_HashSequenceStart, Esys_SequenceUpdate},
    Context, Result, ReturnCode,
};
use log::error;

impl Context {
    // Missing function: HMAC_Start
    // Missing function: MAC_Start

    pub fn hash_sequence_start(
        &mut self,
        hashing_algorithm: HashingAlgorithm,
        auth: Option<Auth>,
    ) -> Result<ObjectHandle> {
        let mut object_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_HashSequenceStart(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.unwrap_or_default().into(),
                    hashing_algorithm.into(),
                    &mut object_handle,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform hash sequence start operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok(ObjectHandle::from(object_handle))
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

    // Missing function: SequenceComplete
    // Missing function: EventSequenceComplete
}
