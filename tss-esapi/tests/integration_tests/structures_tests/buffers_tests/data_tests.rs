// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::structures::Data;
use tss_esapi::tss2_esys::TPM2B_DATA;
// The TPM2B_DATA has a size of 64 bytes

#[test]
fn test_max_sized_data() {
    let _ = Data::try_from([0xff; 64].to_vec()).unwrap();
}

#[test]
fn test_to_large_data() {
    // Removed:
    //    - test_create::test_long_outside_info_create
    //    - test_create_primary::test_long_outside_info_create_primary
    // from the context tests and put here instead.

    let _ = Data::try_from([0xff; 100].to_vec()).unwrap_err();
}

#[test]
fn test_default() {
    {
        let data: Data = Default::default();
        let expected: TPM2B_DATA = Default::default();
        let actual = TPM2B_DATA::from(data);
        assert_eq!(expected.size, actual.size);
        assert_eq!(
            expected.buffer.len(),
            actual.buffer.len(),
            "Buffers don't have the same length"
        );
        assert!(
            expected
                .buffer
                .iter()
                .zip(actual.buffer.iter())
                .all(|(a, b)| a == b),
            "Buffers are not equal"
        );
    }
    {
        let tss_data: TPM2B_DATA = Default::default();
        let expected: Data = Default::default();
        let actual = Data::try_from(tss_data).unwrap();
        assert_eq!(expected, actual);
    }
}

#[test]
fn test_max_sized_data_conversions() {
    let expected_buffer = [0xffu8; Data::MAX_SIZE];
    let native = Data::try_from(expected_buffer.as_slice().to_vec())
        .expect("It should be possible to convert an array of MAX size into a Data object.");
    let tss = TPM2B_DATA::from(native);
    assert_eq!(Data::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_buffer, tss.buffer);
}
