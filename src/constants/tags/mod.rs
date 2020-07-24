// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// Contains structure tag TPM_ST
mod structure;
pub use structure_tag::StructureTag;
pub mod structure_tag {
    pub use super::structure::*;
}
