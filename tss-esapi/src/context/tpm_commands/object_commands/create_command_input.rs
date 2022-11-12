// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ffi::data_zeroize::FfiDataZeroize,
    handles::KeyHandle,
    structures::{Auth, Data, PcrSelectionList, Public, SensitiveCreate, SensitiveData},
    tss2_esys::{ESYS_TR, TPM2B_DATA, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPML_PCR_SELECTION},
    Result,
};
use std::convert::TryInto;
use zeroize::Zeroize;

/// Struct that handles the input of the
/// to the Esys_Create command and zeroizes
/// the data when it gets dropped.
pub struct CreateCommandInputHandler {
    ffi_in_parent_handle: ESYS_TR,
    ffi_in_sensitive: TPM2B_SENSITIVE_CREATE,
    ffi_in_public: TPM2B_PUBLIC,
    ffi_outside_info: TPM2B_DATA,
    ffi_creation_pcr: TPML_PCR_SELECTION,
}

impl CreateCommandInputHandler {
    /// Creates the CreateCommandInputHandler from the inputs
    /// of the 'create' [crate::Context] method.
    ///
    /// # Details
    /// Consumes the input parameters and converts them into their
    /// TSS counterpart and zeroizes all the data when dropped.
    ///
    /// # Arguments
    /// See the input arguments of 'crate' [crate::Context] method.
    ///
    /// # Returns
    /// The created CreateCommandInputHandler.
    ///
    /// # Errors
    /// WrapperErrors if the conversions to the TSS types fails.
    pub(crate) fn create(
        parent_handle: KeyHandle,
        public: Public,
        auth_value: Option<Auth>,
        sensitive_data: Option<SensitiveData>,
        outside_info: Option<Data>,
        creation_pcrs: Option<PcrSelectionList>,
    ) -> Result<Self> {
        Ok(Self {
            ffi_in_parent_handle: parent_handle.into(),
            ffi_in_sensitive: SensitiveCreate::new(
                auth_value.unwrap_or_default(),
                sensitive_data.unwrap_or_default(),
            )
            .try_into()?,
            ffi_in_public: public.try_into()?,
            ffi_outside_info: outside_info.unwrap_or_default().into(),
            ffi_creation_pcr: PcrSelectionList::list_from_option(creation_pcrs).into(),
        })
    }

    /// The 'parentHandle' input parameter
    pub const fn ffi_in_parent_handle(&self) -> ESYS_TR {
        self.ffi_in_parent_handle
    }

    /// The 'inSensitive' input parameter.
    pub const fn ffi_in_sensitive(&self) -> &TPM2B_SENSITIVE_CREATE {
        &self.ffi_in_sensitive
    }

    /// The 'inPublic' input parameter.
    pub const fn ffi_in_public(&self) -> &TPM2B_PUBLIC {
        &self.ffi_in_public
    }

    /// The 'outsideInfo' input parameter.
    pub const fn ffi_outside_info(&self) -> &TPM2B_DATA {
        &self.ffi_outside_info
    }

    /// The 'creationPCR' input parameter.
    pub const fn ffi_creation_pcr(&self) -> &TPML_PCR_SELECTION {
        &self.ffi_creation_pcr
    }
}

impl Zeroize for CreateCommandInputHandler {
    fn zeroize(&mut self) {
        self.ffi_in_parent_handle.zeroize();
        self.ffi_in_sensitive.ffi_data_zeroize();
        self.ffi_in_public.ffi_data_zeroize();
        self.ffi_outside_info.ffi_data_zeroize();
        self.ffi_creation_pcr.ffi_data_zeroize();
    }
}

impl Drop for CreateCommandInputHandler {
    fn drop(&mut self) {
        self.zeroize();
    }
}
