// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_dictionary_attack_lock_reset {
    use crate::common::create_ctx_with_session;
    use tss_esapi::handles::AuthHandle;

    #[test]
    fn test_dictionary_attack_lock_reset() {
        let mut context = create_ctx_with_session();
        context
            .dictionary_attack_lock_reset(AuthHandle::Lockout)
            .unwrap();
    }
}

mod test_dictionary_attack_parameters {
    use crate::common::create_ctx_with_session;
    use tss_esapi::handles::AuthHandle;

    #[test]
    fn test_dictionary_attack_parameters() {
        let mut context = create_ctx_with_session();
        context
            .dictionary_attack_parameters(AuthHandle::Lockout, 10, 300, 300)
            .unwrap();
        // Restore defaults
        context
            .dictionary_attack_parameters(AuthHandle::Lockout, 0, 0, 0)
            .unwrap();
    }
}
