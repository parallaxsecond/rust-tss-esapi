// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::KeyHandle,
    structures::{Data, PcrSelectionList},
    tss2_esys::*,
    utils::Signature,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::ptr::null_mut;

impl Context {
    // Missing function: Certify
    // Missing function: CertifyCreation

    /// Generate a quote on the selected PCRs
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
    pub fn quote(
        &mut self,
        signing_key_handle: KeyHandle,
        qualifying_data: &Data,
        signing_scheme: TPMT_SIG_SCHEME,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<(TPM2B_ATTEST, Signature)> {
        let mut quoted = null_mut();
        let mut signature = null_mut();
        let ret = unsafe {
            Esys_Quote(
                self.mut_context(),
                signing_key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &qualifying_data.clone().into(),
                &signing_scheme,
                &pcr_selection_list.into(),
                &mut quoted,
                &mut signature,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let quoted = unsafe { MBox::<TPM2B_ATTEST>::from_raw(quoted) };
            let signature = unsafe { MBox::from_raw(signature) };
            Ok((*quoted, unsafe { Signature::try_from(*signature)? }))
        } else {
            error!("Error in quoting PCR: {}", ret);
            Err(ret)
        }
    }

    // Missing function: GetSessionAuditDigest
    // Missing function: GestCommandAuditDigest
    // Missing function: GetTime
    // Missing function: CertifyX509
}
