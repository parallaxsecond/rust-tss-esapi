// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! The default callbacks are process-wide, so they are tested in their own
//! binary, away from the integration tests that use tpm2-tss's own backend.
#![cfg(has_esys_set_crypto_callbacks)]

#[allow(dead_code)]
#[path = "integration_tests/common/crypto_callbacks.rs"]
mod crypto_callbacks;
#[allow(dead_code)]
#[path = "integration_tests/common/swtpm.rs"]
mod swtpm;

use std::sync::atomic::{AtomicUsize, Ordering};

/// Called by the `swtpm` module, as in the integration tests' `common`.
fn setup_logging() {
    let _ = env_logger::try_init();
}
use tss_esapi::{
    Context, Error, WrapperErrorKind, constants::SessionType,
    interface_types::algorithm::HashingAlgorithm, structures::SymmetricDefinition,
};

#[test]
fn test_default_callbacks_apply_to_new_contexts() {
    static RANDOM_CALLS: AtomicUsize = AtomicUsize::new(0);
    let callbacks = crypto_callbacks::stub_callbacks(&RANDOM_CALLS);

    // SAFETY: the callbacks follow the ESYS contract, are thread-safe and use
    // only a static counter as userdata.
    unsafe { Context::set_default_crypto_callbacks(&callbacks) }
        .expect("Failed to set default crypto callbacks");
    assert_eq!(
        unsafe { Context::set_default_crypto_callbacks(&callbacks) },
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "A second default should be refused"
    );

    let (_swtpm, tcti) = swtpm::create_tcti();
    let mut context = Context::new(tcti).expect("Failed to create context");
    let _ = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to start session with the default callbacks");
    assert!(
        RANDOM_CALLS.load(Ordering::SeqCst) > 0,
        "A new context did not use the default get_random2b callback"
    );
}
