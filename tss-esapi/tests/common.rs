// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::{env, str::FromStr, sync::Once};

use tss_esapi::{
    attributes::SessionAttributesBuilder,
    constants::{
        algorithm::{Cipher, HashingAlgorithm},
        SessionType,
    },
    Context, Tcti,
};

static LOG_INIT: Once = Once::new();
#[allow(dead_code)]
pub fn setup_logging() {
    LOG_INIT.call_once(|| {
        env_logger::init();
    });
}

#[allow(dead_code)]
pub fn create_tcti() -> Tcti {
    setup_logging();

    match env::var("TEST_TCTI") {
        Err(_) => Tcti::Mssim(Default::default()),
        Ok(tctistr) => Tcti::from_str(&tctistr).expect("Error parsing TEST_TCTI"),
    }
}

#[allow(dead_code)]
pub fn create_ctx_without_session() -> Context {
    let tcti = create_tcti();
    unsafe { Context::new(tcti).unwrap() }
}

#[allow(dead_code)]
pub fn create_ctx_with_session() -> Context {
    let mut ctx = create_ctx_without_session();
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            Cipher::aes_256_cfb(),
            HashingAlgorithm::Sha256,
        )
        .unwrap();
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    ctx.tr_sess_set_attributes(
        session.unwrap(),
        session_attributes,
        session_attributes_mask,
    )
    .unwrap();
    ctx.set_sessions((session, None, None));

    ctx
}
