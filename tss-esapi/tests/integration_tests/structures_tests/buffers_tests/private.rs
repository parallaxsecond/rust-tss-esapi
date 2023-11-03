// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::structures::Private;

#[test]
fn marshall_unmarshall() {
    crate::common::check_marshall_unmarshall(&Private::default());
    let private = Private::try_from([0xff; 100].to_vec()).unwrap();
    crate::common::check_marshall_unmarshall(&private);
}

#[test]
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
