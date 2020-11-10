// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_AC_FIRST, TPM2_AC_LAST, TPM2_HMAC_SESSION_FIRST, TPM2_HMAC_SESSION_LAST, TPM2_HT_AC,
        TPM2_HT_HMAC_SESSION, TPM2_HT_LOADED_SESSION, TPM2_HT_NV_INDEX, TPM2_HT_PCR,
        TPM2_HT_PERMANENT, TPM2_HT_PERSISTENT, TPM2_HT_POLICY_SESSION, TPM2_HT_SAVED_SESSION,
        TPM2_HT_TRANSIENT, TPM2_LOADED_SESSION_FIRST, TPM2_LOADED_SESSION_LAST,
        TPM2_NV_INDEX_FIRST, TPM2_NV_INDEX_LAST, TPM2_PCR_FIRST, TPM2_PCR_LAST,
        TPM2_PERMANENT_FIRST, TPM2_PERMANENT_LAST, TPM2_PERSISTENT_FIRST, TPM2_PERSISTENT_LAST,
        TPM2_POLICY_SESSION_FIRST, TPM2_POLICY_SESSION_LAST, TPM2_TRANSIENT_FIRST,
        TPM2_TRANSIENT_LAST,
    },
    tss2_esys::TPM2_HANDLE,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{From, TryFrom};
use std::stringify;

/// Enum representing the different types of tpm handles
/// of a TPM handle.
///
/// * Details
/// The TPM handles are used
/// to reference shielded locations of various
/// types within the TPM.
///
/// * OBS
/// Do not confuse the TpmHandles with the
/// ESYS [ObjectHandle](crate::handles::ObjectHandle).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum TpmHandle {
    Pcr(PcrTpmHandle),
    NvIndex(NvIndexTpmHandle),
    HmacSession(HmacSessionTpmHandle),
    LoadedSession(LoadedSessionTpmHandle),
    PolicySession(PolicySessionTpmHandle),
    SavedSession(SavedSessionTpmHandle),
    Permanent(PermanentTpmHandle),
    Transient(TransientTpmHandle),
    Persistent(PersistentTpmHandle),
    AttachedComponent(AttachedComponentTpmHandle),
}

impl From<TpmHandle> for TPM2_HANDLE {
    fn from(tpm_handle: TpmHandle) -> TPM2_HANDLE {
        match tpm_handle {
            TpmHandle::Pcr(handle) => handle.value,
            TpmHandle::NvIndex(handle) => handle.value,
            TpmHandle::HmacSession(handle) => handle.value,
            TpmHandle::LoadedSession(handle) => handle.value,
            TpmHandle::PolicySession(handle) => handle.value,
            TpmHandle::SavedSession(handle) => handle.value,
            TpmHandle::Permanent(handle) => handle.value,
            TpmHandle::Transient(handle) => handle.value,
            TpmHandle::Persistent(handle) => handle.value,
            TpmHandle::AttachedComponent(handle) => handle.value,
        }
    }
}

impl TryFrom<TPM2_HANDLE> for TpmHandle {
    type Error = Error;
    fn try_from(tss_tpm_handle: TPM2_HANDLE) -> Result<TpmHandle> {
        let most_significant_byte = tss_tpm_handle.to_be_bytes()[0];
        match most_significant_byte {
            TPM2_HT_PCR => Ok(TpmHandle::Pcr(PcrTpmHandle::new(tss_tpm_handle)?)),
            TPM2_HT_NV_INDEX => Ok(TpmHandle::NvIndex(NvIndexTpmHandle::new(tss_tpm_handle)?)),
            TPM2_HT_HMAC_SESSION => Ok(TpmHandle::HmacSession(HmacSessionTpmHandle::new(
                tss_tpm_handle,
            )?)),
            // HMAC and LOADED has the same type id
            TPM2_HT_POLICY_SESSION => Ok(TpmHandle::PolicySession(PolicySessionTpmHandle::new(
                tss_tpm_handle,
            )?)),
            // POLICY and SAVED has the same type id.
            TPM2_HT_PERMANENT => Ok(TpmHandle::Permanent(PermanentTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_TRANSIENT => Ok(TpmHandle::Transient(TransientTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_PERSISTENT => Ok(TpmHandle::Persistent(PersistentTpmHandle::new(
                tss_tpm_handle,
            )?)),
            TPM2_HT_AC => Ok(TpmHandle::AttachedComponent(
                AttachedComponentTpmHandle::new(tss_tpm_handle)?,
            )),
            _ => {
                error!("Error: Invalid TPM handle type {}", most_significant_byte);
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

/// Macro for creating the specific TPM handle types
macro_rules! create_tpm_handle_type {
    ($handle_type_name:ident, $tpm_handle_kind:path, $tpm_handle_type_id:tt, $tpm_handle_type_first:tt, $tpm_handle_type_last:tt) => {
        #[derive(Debug, Copy, Clone, Eq, PartialEq)]
        pub struct $handle_type_name {
            value: u32,
        }

        impl $handle_type_name {
            pub fn new(value: u32) -> Result<$handle_type_name> {
                if value.to_be_bytes()[0] != $tpm_handle_type_id {
                    error!(
                        "Errro: TPM Handle ID of the input value did not match the {} (!={})",
                        stringify!($handle_type_name),
                        $tpm_handle_type_id
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                // Add +1 to include tpm_handle_type_last in the range
                if !($tpm_handle_type_first..($tpm_handle_type_last + 1)).contains(&value) {
                    error!(
                        "Error: TPM Handle ID is not in range ({}..{})",
                        $tpm_handle_type_first, $tpm_handle_type_last
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                Ok($handle_type_name { value })
            }
        }

        impl From<$handle_type_name> for TpmHandle {
            fn from(specific_tpm_handle: $handle_type_name) -> TpmHandle {
                $tpm_handle_kind(specific_tpm_handle)
            }
        }

        impl TryFrom<TpmHandle> for $handle_type_name {
            type Error = Error;
            fn try_from(general_tpm_handle: TpmHandle) -> Result<$handle_type_name> {
                match general_tpm_handle {
                    $tpm_handle_kind(val) => Ok(val),
                    _ => {
                        error!(
                            "Error: Incorrect tpm handle kind(=={}) when converting to {}",
                            stringify!($tpm_handle_kind),
                            stringify!($handle_type_name)
                        );
                        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                    }
                }
            }
        }

        impl From<$handle_type_name> for TPM2_HANDLE {
            fn from(specific_tpm_handle: $handle_type_name) -> TPM2_HANDLE {
                specific_tpm_handle.value
            }
        }

        impl TryFrom<TPM2_HANDLE> for $handle_type_name {
            type Error = Error;
            fn try_from(tss_tpm_handle: TPM2_HANDLE) -> Result<$handle_type_name> {
                $handle_type_name::new(tss_tpm_handle)
            }
        }
    };
}

// Creates the specific handle types
create_tpm_handle_type!(
    PcrTpmHandle,
    TpmHandle::Pcr,
    TPM2_HT_PCR,
    TPM2_PCR_FIRST,
    TPM2_PCR_LAST
);
create_tpm_handle_type!(
    NvIndexTpmHandle,
    TpmHandle::NvIndex,
    TPM2_HT_NV_INDEX,
    TPM2_NV_INDEX_FIRST,
    TPM2_NV_INDEX_LAST
);
create_tpm_handle_type!(
    HmacSessionTpmHandle,
    TpmHandle::HmacSession,
    TPM2_HT_HMAC_SESSION,
    TPM2_HMAC_SESSION_FIRST,
    TPM2_HMAC_SESSION_LAST
);
create_tpm_handle_type!(
    LoadedSessionTpmHandle,
    TpmHandle::LoadedSession,
    TPM2_HT_LOADED_SESSION,
    TPM2_LOADED_SESSION_FIRST,
    TPM2_LOADED_SESSION_LAST
);
create_tpm_handle_type!(
    PolicySessionTpmHandle,
    TpmHandle::PolicySession,
    TPM2_HT_POLICY_SESSION,
    TPM2_POLICY_SESSION_FIRST,
    TPM2_POLICY_SESSION_LAST
);

create_tpm_handle_type!(
    SavedSessionTpmHandle,
    TpmHandle::SavedSession,
    TPM2_HT_SAVED_SESSION,
    TPM2_POLICY_SESSION_FIRST, // Policy session have the same type as saved session.
    TPM2_POLICY_SESSION_LAST   // so assuming they have the same valid range makes sense.
);
create_tpm_handle_type!(
    PermanentTpmHandle,
    TpmHandle::Permanent,
    TPM2_HT_PERMANENT,
    TPM2_PERMANENT_FIRST,
    TPM2_PERMANENT_LAST
);
create_tpm_handle_type!(
    TransientTpmHandle,
    TpmHandle::Transient,
    TPM2_HT_TRANSIENT,
    TPM2_TRANSIENT_FIRST,
    TPM2_TRANSIENT_LAST
);
create_tpm_handle_type!(
    PersistentTpmHandle,
    TpmHandle::Persistent,
    TPM2_HT_PERSISTENT,
    TPM2_PERSISTENT_FIRST,
    TPM2_PERSISTENT_LAST
);
create_tpm_handle_type!(
    AttachedComponentTpmHandle,
    TpmHandle::AttachedComponent,
    TPM2_HT_AC,
    TPM2_AC_FIRST,
    TPM2_AC_LAST
);
