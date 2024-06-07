// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ffi::data_zeroize::FfiDataZeroize,
    handles::KeyHandle,
    structures::{Auth, Public, SensitiveCreate, SensitiveData},
    tss2_esys::{ESYS_TR, TPM2B_SENSITIVE_CREATE, TPM2B_TEMPLATE},
    Result,
};
use std::convert::TryInto;
use zeroize::Zeroize;

/// Struct that handles the input of the
/// to the Esys_CreateLoaded command and zeroizes
/// the data when it gets dropped.
pub struct CreateLoadedCommandInputHandler {
    ffi_in_parent_handle: ESYS_TR,
    ffi_in_sensitive: TPM2B_SENSITIVE_CREATE,
    // Per Part 3 12.9.1 note 1:
    //   In the general descriptions of TPM2_Create() and TPM2_CreatePrimary() the validations refer to a
    //   TPMT_PUBLIC structure that is in inPublic. For TPM2_CreateLoaded(), inPublic is a
    //   TPM2B_TEMPLATE that may contain a TPMT_PUBLIC that is used for object creation. For object
    //   derivation, the unique field can contain a label and context that are used in the derivation process.
    //   To allow both the TPMT_PUBLIC and the derivation variation, a TPM2B_TEMPLATE is used. When
    //   referring to the checks in TPM2_Create() and TPM2_CreatePrimary(), TPM2B_TEMPLATE should
    //   be assumed to contain a TPMT_PUBLIC.
    ffi_in_public: TPM2B_TEMPLATE,
}

impl CreateLoadedCommandInputHandler {
    /// Creates the CreateLoadedCommandInputHandler from the inputs
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
    /// The created CreateLoadedCommandInputHandler.
    ///
    /// # Errors
    /// WrapperErrors if the conversions to the TSS types fails.
    pub(crate) fn create(
        parent_handle: KeyHandle,
        auth_value: Option<Auth>,
        sensitive_data: Option<SensitiveData>,
        public: Public,
    ) -> Result<Self> {
        Ok(Self {
            ffi_in_parent_handle: parent_handle.into(),
            ffi_in_sensitive: SensitiveCreate::new(
                auth_value.unwrap_or_default(),
                sensitive_data.unwrap_or_default(),
            )
            .try_into()?,
            ffi_in_public: public.try_into()?,
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
    pub const fn ffi_in_public(&self) -> &TPM2B_TEMPLATE {
        &self.ffi_in_public
    }
}

impl Zeroize for CreateLoadedCommandInputHandler {
    fn zeroize(&mut self) {
        self.ffi_in_parent_handle.zeroize();
        self.ffi_in_sensitive.ffi_data_zeroize();
        self.ffi_in_public.ffi_data_zeroize();
    }
}

impl Drop for CreateLoadedCommandInputHandler {
    fn drop(&mut self) {
        self.zeroize();
    }
}
