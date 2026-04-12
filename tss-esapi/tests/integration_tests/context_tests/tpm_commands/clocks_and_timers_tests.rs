// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_read_clock {
    use crate::common::create_ctx_without_session;

    #[test]
    fn test_read_clock() {
        let mut context = create_ctx_without_session();
        let time_info = context.read_clock().unwrap();
        assert!(time_info.time() > 0);
    }
}

mod test_clock_set {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{handles::AuthHandle, interface_types::session_handles::AuthSession};

    #[test]
    fn test_clock_set() {
        let mut context = create_ctx_without_session();
        let time_info = context.read_clock().unwrap();
        // Advance the clock forward
        let new_time = time_info.clock_info().clock() + 100_000;
        context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.clock_set(AuthHandle::Owner, new_time)
            })
            .unwrap();
    }
}
