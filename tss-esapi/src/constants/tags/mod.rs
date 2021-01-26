// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// Contains property tag TPM_PT
mod property;
pub use property::PropertyTag;
pub mod property_tag {
    pub use super::property::*;
}

/// Contains structure tag TPM_ST
mod structure;
pub use structure_tag::StructureTag;
pub mod structure_tag {
    pub use super::structure::*;
}
