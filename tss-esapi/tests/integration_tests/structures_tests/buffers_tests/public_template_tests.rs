// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    Error, WrapperErrorKind,
    structures::{Public, PublicTemplate},
    tss2_esys::TPM2B_TEMPLATE,
};

#[test]
fn test_byte_conversions() {
    let expected = vec![0xA5; PublicTemplate::MAX_SIZE];
    let from_slice = PublicTemplate::try_from(expected.as_slice()).unwrap();
    let from_vec = PublicTemplate::try_from(expected.clone()).unwrap();

    assert_eq!(expected.as_slice(), from_slice.as_bytes());
    assert_eq!(from_slice, from_vec);
}

#[test]
fn test_rejects_oversized_data() {
    assert_eq!(
        Error::WrapperError(WrapperErrorKind::WrongParamSize),
        PublicTemplate::try_from(vec![0u8; PublicTemplate::MAX_SIZE + 1]).unwrap_err()
    );
}

#[test]
fn test_tpm2b_template_conversion() {
    let expected = vec![0x5A; PublicTemplate::MAX_SIZE];
    let template = PublicTemplate::try_from(expected.clone()).unwrap();
    let ffi_template = TPM2B_TEMPLATE::from(template.clone());

    assert_eq!(expected.len(), ffi_template.size as usize);
    assert_eq!(expected.as_slice(), &ffi_template.buffer[..expected.len()]);
    assert_eq!(template, PublicTemplate::try_from(ffi_template).unwrap());
}

#[test]
fn test_public_conversion_and_marshalling() {
    crate::common::publics().iter().for_each(|public| {
        let template = PublicTemplate::try_from(public.clone()).unwrap();
        crate::common::check_marshall_unmarshall(&template);
        assert_eq!(
            public,
            &Public::try_from(template).expect("Failed to decode PublicTemplate")
        );
    });
}
