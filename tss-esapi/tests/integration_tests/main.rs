// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "integration-tests")]

#[path = "common/mod.rs"]
mod common;

#[cfg(feature = "abstraction")]
mod abstraction_tests;
mod attributes_tests;
mod constants_tests;
mod context_tests;
mod error_tests;
mod handles_tests;
mod interface_types_tests;
mod structures_tests;
mod tcti_ldr_tests;
mod traits;
mod utils_tests;
