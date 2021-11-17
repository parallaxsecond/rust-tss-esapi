// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::{
    structures::*,
    traits::{Marshall, UnMarshall},
};

use crate::common::setup_logging;

#[test]
fn test_marshal_unmarshal_null() {
    setup_logging();

    let sig = Signature::Null;
    let sig_vec = sig.marshall().expect("Failed to marshall signature");
    let new_sig = Signature::unmarshall(sig_vec.as_ref()).expect("Failed to unmarshal signature");

    assert_eq!(new_sig, sig);
}
