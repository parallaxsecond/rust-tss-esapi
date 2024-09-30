// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::impl_mu_standard;
use std::mem::size_of;
use tss_esapi_sys::_PRIVATE;

const TPM2B_PRIVATE_BUFFER_SIZE: usize = size_of::<_PRIVATE>();

buffer_type!(Private, TPM2B_PRIVATE_BUFFER_SIZE, TPM2B_PRIVATE);

impl_mu_standard!(Private, TPM2B_PRIVATE);

cfg_if::cfg_if! {
    if #[cfg(feature = "serde")] {
        use crate::traits::{Marshall, UnMarshall};
        impl serde::Serialize for Private {
            /// Serialize the [Private] data into it's bytes representation of the TCG
            /// TPM2B_PRIVATE structure.
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                let bytes = self.marshall().map_err(serde::ser::Error::custom)?;
                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> serde::Deserialize<'de> for Private {
            /// Deserialize the [Private] data from it's bytes representation of the TCG
            /// TPM2B_PRIVATE structure.
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let bytes = <Vec<u8>>::deserialize(deserializer)?;
                Self::unmarshall(&bytes).map_err(serde::de::Error::custom)
            }
        }
    }
}
