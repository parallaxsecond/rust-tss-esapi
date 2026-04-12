// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_pp_commands {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{handles::AuthHandle, structures::CommandCodeList};

    #[test]
    #[ignore = "Platform-specific command"]
    fn test_pp_commands() {
        let mut context = create_ctx_with_session();
        context
            .pp_commands(
                AuthHandle::Platform,
                CommandCodeList::new(),
                CommandCodeList::new(),
            )
            .unwrap();
    }
}

mod test_set_algorithm_set {
    // SetAlgorithmSet is a platform-specific command that may not be
    // supported on all TPMs or simulators.
    use crate::common::create_ctx_with_session;
    use tss_esapi::handles::AuthHandle;

    #[test]
    #[ignore = "Platform-specific command"]
    fn test_set_algorithm_set() {
        let mut context = create_ctx_with_session();
        context.set_algorithm_set(AuthHandle::Platform, 0).unwrap();
    }
}
