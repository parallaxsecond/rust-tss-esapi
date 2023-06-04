// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::traits::{Marshall, UnMarshall};

pub fn check_marshall_unmarshall<T: Marshall + UnMarshall + Eq + std::fmt::Debug>(val: &T) {
    let buf = val.marshall().expect("Failed to marshall value");

    let unmarshalled = T::unmarshall(&buf).expect("Failed to unmarshall");

    assert_eq!(val, &unmarshalled);
}

pub fn check_marshall_unmarshall_offset<T: Marshall + UnMarshall + Eq + std::fmt::Debug>(val: &T) {
    let mut buf = val.marshall().expect("Failed to marshall value");
    let len = buf.len();
    let mut offset = 0;

    buf.append(&mut buf.clone());
    buf.append(&mut vec![0xff; 256]);

    let unmarshalled_one =
        T::unmarshall_offset(&buf, &mut offset).expect("Failed to unmarshall first copy");
    assert_eq!(offset, len as u64);
    assert_eq!(val, &unmarshalled_one);

    let unmarshalled_two =
        T::unmarshall_offset(&buf, &mut offset).expect("Failed to unmarshall second copy");
    assert_eq!(offset, (len * 2) as u64);
    assert_eq!(val, &unmarshalled_two);
}
