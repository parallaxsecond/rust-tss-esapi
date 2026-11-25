// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::common::{create_ctx_without_session, crypto_callbacks::stub_callbacks};
use std::sync::atomic::{AtomicUsize, Ordering};
use tss_esapi::{
    Error, ReturnCode,
    constants::{SessionType, return_code::BaseError},
    interface_types::algorithm::HashingAlgorithm,
    structures::SymmetricDefinition,
};

#[test]
fn test_missing_callback_is_callback_null() {
    static RANDOM_CALLS: AtomicUsize = AtomicUsize::new(0);
    let mut context = create_ctx_without_session();
    let mut callbacks = stub_callbacks(&RANDOM_CALLS);
    callbacks.get_random2b = None;

    // SAFETY: the callbacks follow the ESYS contract and need no userdata
    // beyond a static counter.
    let error = unsafe { context.set_crypto_callbacks(&callbacks) }
        .expect_err("Setting callbacks without get_random2b should fail");
    match error {
        Error::TssError(ReturnCode::Esapi(esapi_rc)) => {
            assert_eq!(esapi_rc.base_error(), BaseError::CallbackNull)
        }
        other => panic!("Expected an ESAPI CallbackNull error, got {other:?}"),
    }
}

#[test]
fn test_set_callbacks_are_used() {
    static RANDOM_CALLS: AtomicUsize = AtomicUsize::new(0);
    let mut context = create_ctx_without_session();

    // SAFETY: as above.
    unsafe { context.set_crypto_callbacks(&stub_callbacks(&RANDOM_CALLS)) }
        .expect("Failed to set crypto callbacks");

    // An unsalted, unbound session needs only a caller nonce from the backend.
    let _ = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to start session with the stub callbacks");
    assert!(
        RANDOM_CALLS.load(Ordering::SeqCst) > 0,
        "ESYS did not use the installed get_random2b callback"
    );
}
