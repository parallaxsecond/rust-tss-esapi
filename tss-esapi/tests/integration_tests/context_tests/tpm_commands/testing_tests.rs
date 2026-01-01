// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_self_test {
    use serial_test::serial;
    use crate::common::create_ctx_without_session;

    #[test]
    #[serial]
    fn test_self_test() {
        let mut context = create_ctx_without_session();
        context.self_test(false).unwrap();
        context.self_test(true).unwrap();
    }
}

mod test_get_test_result {
    use serial_test::serial;
    use crate::common::create_ctx_without_session;
    #[test]
    #[serial]
    fn test_get_test_result() {
        let mut context = create_ctx_without_session();
        let (_, rc) = context.get_test_result().unwrap();
        rc.unwrap();
    }
}
