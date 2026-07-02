// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod test_read_clock {
    use crate::common::create_ctx_without_session;
    use std::{thread::sleep, time::Duration};

    #[test]
    fn test_read_clock() {
        let mut context = create_ctx_without_session();

        let first_time_info = context.read_clock().unwrap();
        sleep(Duration::from_millis(10));
        let second_time_info = context.read_clock().unwrap();

        assert!(second_time_info.time() >= first_time_info.time());
        assert!(second_time_info.clock_info().clock() >= first_time_info.clock_info().clock());
    }
}

mod test_clock_set {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{handles::AuthHandle, interface_types::session_handles::AuthSession};

    #[test]
    fn test_clock_set() {
        let mut context = create_ctx_without_session();
        let time_info = context.read_clock().unwrap();
        let new_time = time_info.clock_info().clock() + 100_000;

        context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.clock_set(AuthHandle::Owner, new_time)
            })
            .unwrap();

        assert!(context.read_clock().unwrap().clock_info().clock() >= new_time);
    }
}

mod test_clock_rate_adjust {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        constants::ClockAdjust, handles::AuthHandle, interface_types::session_handles::AuthSession,
    };

    #[test]
    fn test_clock_rate_adjust_no_change() {
        let mut context = create_ctx_without_session();

        context
            .execute_with_session(Some(AuthSession::Password), |ctx| {
                ctx.clock_rate_adjust(AuthHandle::Owner, ClockAdjust::NoChange)
            })
            .unwrap();
    }
}
