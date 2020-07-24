// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// This module contains both the constants defined in the TSS specification (tss module)
/// but also the internal representaion of the TSS constants.

/// Representation of the constants defined in the
/// Constants -> TPM_ALG_ID section of the specfication
pub mod algorithm;

/// The contants defined in the TSS specification.
#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    clippy::all
)]
pub mod tss;

/// Representation of the different tag constants.
/// Constants -> TPM_ST, TPM_PT, TPM_PCR_PT
pub mod tags;

/// Representation of the return code TSS2_RC (TPM_RC)
pub mod response_code;
