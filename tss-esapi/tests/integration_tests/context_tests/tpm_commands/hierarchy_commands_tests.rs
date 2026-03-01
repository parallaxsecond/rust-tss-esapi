// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_create_primary {
    use serial_test::serial;
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use tss_esapi::{
        handles::ObjectHandle, interface_types::reserved_handles::Hierarchy, structures::Auth,
    };

    #[test]
    #[serial]
    fn test_create_primary() {
        let mut context = create_ctx_with_session();
        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth),
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        assert!(ObjectHandle::from(key_handle) != ObjectHandle::Null);
    }
}

mod test_clear {
    use serial_test::serial;
    use crate::common::create_ctx_with_session;
    use tss_esapi::handles::AuthHandle;

    #[test]
    #[serial]
    fn test_clear() {
        let mut context = create_ctx_with_session();

        context.clear(AuthHandle::Platform).unwrap();
    }
}

mod test_clear_control {
    use serial_test::serial;
    use crate::common::create_ctx_with_session;
    use tss_esapi::handles::AuthHandle;
    #[test]
    #[serial]
    fn test_clear_control() {
        let mut context = create_ctx_with_session();

        context.clear(AuthHandle::Platform).unwrap();
        context.clear_control(AuthHandle::Platform, true).unwrap();
        context.clear(AuthHandle::Platform).unwrap_err();
        context.clear_control(AuthHandle::Platform, false).unwrap();
        context.clear(AuthHandle::Platform).unwrap();
    }
}

mod test_change_auth {
    use serial_test::serial;
    use crate::common::{create_ctx_with_session, decryption_key_pub};
    use tss_esapi::{
        handles::AuthHandle, interface_types::reserved_handles::Hierarchy, structures::Auth,
    };

    #[test]
    #[serial]
    fn test_object_change_auth() {
        let mut context = create_ctx_with_session();

        let prim_key_handle = context
            .create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap()
            .key_handle;
        let keyresult = context
            .create(
                prim_key_handle,
                decryption_key_pub(),
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let loaded_key = context
            .load(
                prim_key_handle,
                keyresult.out_private,
                keyresult.out_public.clone(),
            )
            .unwrap();

        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let new_key_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        let new_private = context
            .object_change_auth(loaded_key.into(), prim_key_handle.into(), new_key_auth)
            .unwrap();
        context
            .load(prim_key_handle, new_private, keyresult.out_public)
            .unwrap();
    }

    #[test]
    #[serial]
    fn test_hierarchy_change_auth() {
        let mut context = create_ctx_with_session();

        let mut random_digest = vec![0u8; 16];
        getrandom::getrandom(&mut random_digest).unwrap();
        let new_auth = Auth::from_bytes(random_digest.as_slice()).unwrap();

        // NOTE: If this test failed on your system, you are probably running it against a
        //  real (hardware) TPM or one that is provisioned. This hierarchy is supposed to be
        //  used by the platform. It's used in this test because if we fail at restoring auth,
        //  it should not be a big deal on a software TPM, and it won't impact the other tests.
        context
            .hierarchy_change_auth(AuthHandle::Platform, new_auth)
            .unwrap();
        context
            .hierarchy_change_auth(AuthHandle::Platform, Default::default())
            .unwrap();
    }
}
