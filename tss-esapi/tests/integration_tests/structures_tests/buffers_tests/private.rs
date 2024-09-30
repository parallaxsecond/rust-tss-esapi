// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{structures::Private, tss2_esys::TPM2B_PRIVATE};

#[test]
fn marshall_unmarshall() {
    crate::common::check_marshall_unmarshall(&Private::default());
    let private = Private::try_from([0xff; 100].to_vec()).unwrap();
    crate::common::check_marshall_unmarshall(&private);
}

#[test]
#[cfg(feature = "serde")]
fn serialise_deserialise() {
    crate::common::check_serialise_deserialise(&Private::default());
    let private = Private::try_from([0xff; 100].to_vec()).unwrap();
    crate::common::check_serialise_deserialise(&private);
}

#[test]
fn marshall_unmarshall_offset() {
    crate::common::check_marshall_unmarshall_offset(&Private::default());
    let private = Private::try_from([0xff; 100].to_vec()).unwrap();
    crate::common::check_marshall_unmarshall_offset(&private);
}

#[test]
fn test_max_sized_private_conversions() {
    let expected_buffer = [0xffu8; Private::MAX_SIZE];
    let native = Private::try_from(expected_buffer.as_slice().to_vec())
        .expect("It should be possible to convert an array of MAX size into a Private object.");
    let tss = TPM2B_PRIVATE::from(native);
    assert_eq!(Private::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_buffer, tss.buffer);
}
