// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_pp_commands {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{handles::AuthHandle, structures::CommandCodeList};

    #[test]
    #[ignore = "the swtpm test setup cannot assert the Physical Presence required by TPM2_PP_Commands"]
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
    use crate::common::create_ctx_with_session;
    use tss_esapi::{constants::PropertyTag, handles::AuthHandle};

    #[test]
    fn test_set_algorithm_set() {
        let mut context = create_ctx_with_session();
        let algorithm_set = context
            .get_tpm_property(PropertyTag::AlgorithmSet)
            .unwrap()
            .expect("swtpm did not report its current algorithm set");

        context
            .set_algorithm_set(AuthHandle::Platform, algorithm_set)
            .unwrap();
    }
}
