// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::structures::{Digest, DigestList};
use tss_esapi::tss2_esys::{TPM2B_DIGEST, TPML_DIGEST};

#[test]
fn test_conversion_from_tss_digest_list() {
    let mut expected_digests = Vec::<Digest>::new();
    let mut tss_digest_list: TPML_DIGEST = Default::default();
    for i in 0..3 {
        let mut tss_digest = TPM2B_DIGEST {
            size: 32,
            ..Default::default()
        };
        tss_digest.buffer[..32].copy_from_slice(&[i; 32]);
        expected_digests.push(Digest::try_from(tss_digest).unwrap());
        tss_digest_list.digests[i as usize] = tss_digest;
        tss_digest_list.count += 1;
    }

    let digest_list = DigestList::try_from(tss_digest_list).unwrap();
    assert_eq!(digest_list.value().len(), tss_digest_list.count as usize);
    for actual_digest in digest_list.value().iter() {
        match expected_digests
            .iter()
            .position(|v| v.value() == actual_digest.value())
        {
            Some(pos) => {
                expected_digests.remove(pos);
            }
            None => panic!("Digest did not exist in the expected digests"),
        }
    }
    assert_eq!(expected_digests.len(), 0);
}

#[test]
fn test_add_exceeding_max_limit() {
    let digest = Digest::try_from(vec![1, 2, 3, 4, 5, 6, 7]).unwrap();
    let mut digest_list: DigestList = Default::default();
    for _ in 0..DigestList::MAX_SIZE {
        digest_list.add(digest.clone()).unwrap();
    }
    digest_list.add(digest).unwrap_err();
}

#[test]
fn test_conversion_from_tss_digest_list_with_count_below_min() {
    // These tests might be removed in the future becuase the
    // min limit only applies when the DigestList is used as
    // argument to policy_or.
    let mut tss_digest_list: TPML_DIGEST = Default::default();
    let mut tss_digest = TPM2B_DIGEST {
        size: 32,
        ..Default::default()
    };
    tss_digest.buffer[..32].copy_from_slice(&[1; 32]);
    tss_digest_list.count = 1;
    tss_digest_list.digests[0] = tss_digest;

    let _ = DigestList::try_from(tss_digest_list).unwrap_err();
}

#[test]
fn test_conversion_to_tss_digest_list_with_count_below_min() {
    // These tests might be removed in the future becuase the
    // min limit only applies when the DigestList is used as
    // argument to policy_or.
    let mut digest_list: DigestList = Default::default();
    digest_list
        .add(Digest::try_from(vec![1, 2, 3, 4, 5, 6, 7]).unwrap())
        .unwrap();
    if TPML_DIGEST::try_from(digest_list).is_ok() {
        panic!("No error regarding a digest list that is to small was reported.");
    }
}
