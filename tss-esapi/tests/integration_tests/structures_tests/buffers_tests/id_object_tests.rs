// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{structures::IdObject, tss2_esys::TPM2B_ID_OBJECT};
#[test]
fn test_max_sized_id_object_conversions() {
    let expected_credential = [0xffu8; IdObject::MAX_SIZE];
    let native = IdObject::try_from(expected_credential.as_slice().to_vec())
        .expect("It should be possible to convert an array of MAX size into a IdObject object.");
    let tss = TPM2B_ID_OBJECT::from(native);
    assert_eq!(IdObject::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_credential, tss.credential);
}
