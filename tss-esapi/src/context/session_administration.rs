// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    attributes::{SessionAttributes, SessionAttributesMask},
    handles::SessionHandle,
    interface_types::session_handles::AuthSession,
    tss2_esys::{Esys_TRSess_GetAttributes, Esys_TRSess_SetAttributes},
    Context, Result, ReturnCode,
};
use log::error;
use std::convert::TryInto;

impl Context {
    /// Set the given attributes on a given session.
    pub fn tr_sess_set_attributes(
        &mut self,
        session: AuthSession,
        attributes: SessionAttributes,
        mask: SessionAttributesMask,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_TRSess_SetAttributes(
                    self.mut_context(),
                    SessionHandle::from(session).into(),
                    attributes.try_into()?,
                    mask.try_into()?,
                )
            },
            |ret| {
                error!("Error when setting session attributes: {:#010X}", ret);
            },
        )
    }

    /// Get session attribute flags.
    pub fn tr_sess_get_attributes(&mut self, session: AuthSession) -> Result<SessionAttributes> {
        let mut flags = 0;
        ReturnCode::ensure_success(
            unsafe {
                Esys_TRSess_GetAttributes(
                    self.mut_context(),
                    SessionHandle::from(session).into(),
                    &mut flags,
                )
            },
            |ret| {
                error!("Error when getting session attributes: {:#010X}", ret);
            },
        )?;
        Ok(SessionAttributes(flags))
    }

    // Missing function: Esys_TRSess_GetNonceTPM
}
