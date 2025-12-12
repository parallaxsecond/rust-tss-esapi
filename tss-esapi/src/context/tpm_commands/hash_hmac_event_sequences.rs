// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::ObjectHandle, interface_types::algorithm::HashingAlgorithm, structures::Auth,
    tss2_esys::Esys_HashSequenceStart, Context, Result, ReturnCode,
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

    // Missing function: SequenceUpdate
    // Missing function: SequenceComplete
    // Missing function: EventSequenceComplete
}
