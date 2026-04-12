// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_set_command_code_audit_status {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        handles::AuthHandle, interface_types::algorithm::HashingAlgorithm,
        structures::CommandCodeList,
    };

    #[test]
    fn test_set_command_code_audit_status() {
        let mut context = create_ctx_with_session();
        context
            .set_command_code_audit_status(
                AuthHandle::Owner,
                HashingAlgorithm::Sha256,
                CommandCodeList::new(),
                CommandCodeList::new(),
            )
            .unwrap();
    }
}
