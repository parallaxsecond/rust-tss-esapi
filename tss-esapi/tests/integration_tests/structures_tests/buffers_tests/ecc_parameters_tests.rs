// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{structures::EccParameter, tss2_esys::TPM2B_ECC_PARAMETER};
#[test]
fn test_max_sized_ecc_parameter_conversions() {
    let expected_buffer: [u8; 128] = [0xffu8; EccParameter::MAX_SIZE];
    let native = EccParameter::try_from(expected_buffer.as_slice().to_vec()).expect(
        "It should be possible to convert an array of MAX size into a EccParameter object.",
    );
    let tss = TPM2B_ECC_PARAMETER::from(native);
    assert_eq!(EccParameter::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_buffer, tss.buffer);
}
