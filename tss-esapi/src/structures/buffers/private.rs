// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::impl_mu_standard;
use crate::traits::{Marshall, UnMarshall};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tss_esapi_sys::_PRIVATE;

buffer_type!(Private, ::std::mem::size_of::<_PRIVATE>(), TPM2B_PRIVATE);

impl_mu_standard!(Private, TPM2B_PRIVATE);

impl Serialize for Private {
    /// Serialise the [Private] data into it's bytes representation of the TCG
    /// TPM2B_PRIVATE structure.
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.marshall().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for Private {
    /// Deserialise the [Private] data from it's bytes representation of the TCG
    /// TPM2B_PRIVATE structure.
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <Vec<u8>>::deserialize(deserializer)?;
        Self::unmarshall(&bytes).map_err(serde::de::Error::custom)
    }
}
