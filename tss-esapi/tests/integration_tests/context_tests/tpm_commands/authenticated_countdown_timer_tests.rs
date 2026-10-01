// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_act_set_timeout {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{handles::ObjectHandle, tss2_esys::ESYS_TR_RH_ACT_0};

    #[test]
    #[ignore = "swtpm does not support TPM2_ACT_SetTimeout"]
    fn test_act_set_timeout() {
        let mut context = create_ctx_with_session();

        let act_handle = ObjectHandle::from(ESYS_TR_RH_ACT_0);

        context
            .act_set_timeout(act_handle, 60)
            .expect("Failed to set ACT timeout");
    }
}
