// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{TryFrom, TryInto};
use tss_esapi::{structures::Digest, tss2_esys::TPM2B_DIGEST};
// Digest has some custom functions for conversion to [u8; N] for common values of N

#[test]
fn test_correctly_sized_digests() {
    // N = 20
    let sha1_ex = Digest::try_from((1..21).collect::<Vec<u8>>()).unwrap();
    let sha1: [u8; 20] = sha1_ex.try_into().unwrap();
    assert_eq!(sha1.to_vec(), (1..21).collect::<Vec<u8>>());
    // N = 32
    let sha256_ex = Digest::try_from((1..33).collect::<Vec<u8>>()).unwrap();
    let sha256: [u8; 32] = sha256_ex.try_into().unwrap();
    assert_eq!(sha256.to_vec(), (1..33).collect::<Vec<u8>>());
    // N = 48
    let sha384_ex = Digest::try_from((1..49).collect::<Vec<u8>>()).unwrap();
    let sha384: [u8; 48] = sha384_ex.try_into().unwrap();
    assert_eq!(sha384.to_vec(), (1..49).collect::<Vec<u8>>());
    // N = 64
    let sha512_ex = Digest::try_from((1..65).collect::<Vec<u8>>()).unwrap();
    let sha512: [u8; 64] = sha512_ex.try_into().unwrap();
    assert_eq!(sha512.to_vec(), (1..65).collect::<Vec<u8>>());
}

#[test]
fn test_incorrectly_sized_digests() {
    // This test uses .err().unwrap() to get around the fact that [u8; N] is only
    //  Debug if N is LengthAtMost32, since .unwrap_err() requires T ([u8; N]): Debug
    // N = 20
    let example = Digest::try_from([0xff; 10].to_vec()).unwrap();
    TryInto::<[u8; 20]>::try_into(example).err().unwrap();
    // N = 32
    let example = Digest::try_from([0xff; 10].to_vec()).unwrap();
    TryInto::<[u8; 32]>::try_into(example).err().unwrap();
    // N = 48
    let example = Digest::try_from([0xff; 10].to_vec()).unwrap();
    TryInto::<[u8; 48]>::try_into(example).err().unwrap();
    // N = 64
    let example = Digest::try_from([0xff; 10].to_vec()).unwrap();
    TryInto::<[u8; 64]>::try_into(example).err().unwrap();
}

#[test]
fn test_max_sized_digest_conversions() {
    let expected_buffer = [0xffu8; Digest::MAX_SIZE];
    let native = Digest::try_from(expected_buffer.as_slice().to_vec())
        .expect("It should be possible to convert an array of MAX size into a Digest object.");
    let tss = TPM2B_DIGEST::from(native);
    assert_eq!(Digest::MAX_SIZE, tss.size as usize);
    // This will be a compiler error if the max size does not match the TSS buffer size.
    assert_eq!(expected_buffer, tss.buffer);
}
