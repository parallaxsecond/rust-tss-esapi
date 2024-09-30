// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{structures::EncryptedSecret, tss2_esys::TPM2B_ENCRYPTED_SECRET};
#[test]
fn test_max_sized_ecc_parameter_conversions() {
    let expected_secret = [0xffu8; EncryptedSecret::MAX_SIZE];
    let native = EncryptedSecret::try_from(expected_secret.as_slice().to_vec()).expect(
        "It should be possible to convert an array of MAX size into a EncryptedSecret object.",
    );
    let tss = TPM2B_ENCRYPTED_SECRET::from(native);
    assert_eq!(EncryptedSecret::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_secret, tss.secret);
}
