// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use serde::{de::DeserializeOwned, Serialize};
use tss_esapi::traits::{Marshall, UnMarshall};

pub fn check_serialise_deserialise<
    T: Serialize + DeserializeOwned + Marshall + UnMarshall + Eq + std::fmt::Debug,
>(
    val: &T,
) {
    let json = serde_json::to_vec(val).expect("Failed to serialise value");

    let unmarshalled: T = serde_json::from_slice(&json).expect("Failed to deserialise");

    assert_eq!(val, &unmarshalled);
}
