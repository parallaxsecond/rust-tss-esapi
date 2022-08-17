use crate::{
    handles::KeyHandle,
    structures::{
        Auth, Data, PcrSelectionList, Public, PublicBuffer, SensitiveCreate, SensitiveCreateBuffer,
        SensitiveData,
    },
    traits::InPlaceFfiDataZeroizer,
    tss2_esys::{ESYS_TR, TPM2B_DATA, TPM2B_PUBLIC, TPM2B_SENSITIVE_CREATE, TPML_PCR_SELECTION},
    Result,
};
use std::convert::TryInto;
use zeroize::Zeroize;

/// Struct that handles the input of the
/// to the Esys_Create command and zeroizes
/// the data when it gets dropped.
pub struct CreateInputHandler {
    ffi_in_parent_handle: ESYS_TR,
    ffi_in_sensitive: TPM2B_SENSITIVE_CREATE,
    ffi_in_public: TPM2B_PUBLIC,
    ffi_outside_info: TPM2B_DATA,
    ffi_creation_pcr: TPML_PCR_SELECTION,
}

impl CreateInputHandler {
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

    pub const fn ffi_in_parent_handle(&self) -> ESYS_TR {
        self.ffi_in_parent_handle
    }

    pub const fn ffi_in_sensitive(&self) -> &TPM2B_SENSITIVE_CREATE {
        &self.ffi_in_sensitive
    }

    pub const fn ffi_in_public(&self) -> &TPM2B_PUBLIC {
        &self.ffi_in_public
    }

    pub const fn ffi_outside_info(&self) -> &TPM2B_DATA {
        &self.ffi_outside_info
    }

    pub const fn ffi_creation_pcr(&self) -> &TPML_PCR_SELECTION {
        &self.ffi_creation_pcr
    }
}

impl Zeroize for CreateInputHandler {
    fn zeroize(&mut self) {
        self.ffi_in_parent_handle.zeroize();
        SensitiveCreateBuffer::zeroize_ffi_data_in_place(&mut self.ffi_in_sensitive);
        PublicBuffer::zeroize_ffi_data_in_place(&mut self.ffi_in_public);
        Data::zeroize_ffi_data_in_place(&mut self.ffi_outside_info);
        PcrSelectionList::zeroize_ffi_data_in_place(&mut self.ffi_creation_pcr);
    }
}

impl Drop for CreateInputHandler {
    fn drop(&mut self) {
        self.zeroize();
    }
}
