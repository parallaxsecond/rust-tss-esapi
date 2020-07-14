// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod sensitive;

pub use sensitive_data::SensitiveData;
pub mod sensitive_data {
    pub use super::sensitive::data::*;
}
