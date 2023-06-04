// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn test_u32_marshall_unmarshall() {
    let val = 0xdeadbeef_u32;
    crate::common::check_marshall_unmarshall(&val);
    crate::common::check_marshall_unmarshall_offset(&val);
}
