// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::TpmHandle,
    interface_types::{data_handles::Saved, reserved_handles::Hierarchy},
    structures::TpmContextData,
    traits::impl_mu_standard,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMS_CONTEXT,
    Error, Result,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryFrom;

/// Structure holding the content of a TPM context.
#[derive(Debug, Clone)]
pub struct SavedTpmContext {
    sequence: u64,
    saved_handle: Saved,
    hierarchy: Hierarchy,
    context_blob: TpmContextData,
}

impl SavedTpmContext {
    /// The sequence parameter
    ///
    /// # Details
    /// "The sequence parameter is used to differentiate the contexts and to allow the TPM to create a different
    ///  encryption key for each context."
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The saved handle.
    pub const fn saved_handle(&self) -> Saved {
        self.saved_handle
    }

    /// The hierarchy for the saved context.
    pub const fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }

    /// The context blob.
    ///
    /// # Details
    /// "This is the hierarchy ([Hierarchy]) for the saved context and determines the proof value used
    ///  in the construction of the encryption and integrity values for the context. For session and sequence
    ///  contexts, the hierarchy is [Hierarchy::Null]. The hierarchy for a transient object may be [Hierarchy::Null]
    ///  but it is not required."
    pub fn context_blob(&self) -> &TpmContextData {
        &self.context_blob
    }
}

impl TryFrom<TPMS_CONTEXT> for SavedTpmContext {
    type Error = Error;

    fn try_from(tss: TPMS_CONTEXT) -> Result<SavedTpmContext> {
        Ok(SavedTpmContext {
            sequence: tss.sequence,
            saved_handle: Saved::try_from(tss.savedHandle)?,
            hierarchy: TpmHandle::try_from(tss.hierarchy).and_then(Hierarchy::try_from)?,
            context_blob: TpmContextData::try_from(tss.contextBlob)?,
        })
    }
}

impl From<SavedTpmContext> for TPMS_CONTEXT {
    fn from(native: SavedTpmContext) -> TPMS_CONTEXT {
        TPMS_CONTEXT {
            sequence: native.sequence,
            savedHandle: native.saved_handle.into(),
            hierarchy: TpmHandle::from(native.hierarchy).into(),
            contextBlob: native.context_blob.into(),
        }
    }
}

impl_mu_standard!(SavedTpmContext, TPMS_CONTEXT);

impl Serialize for SavedTpmContext {
    /// Serialize the [SavedTpmContext] data into it's bytes representation of the TCG
    /// TPMT_PUBLIC structure.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.marshall().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for SavedTpmContext {
    /// Deserialize the [Public] data from it's bytes representation of the TCG
    /// TPMT_PUBLIC structure.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::unmarshall(&bytes).map_err(serde::de::Error::custom)
    }
}
