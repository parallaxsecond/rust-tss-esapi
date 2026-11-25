// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Stub ESYS crypto callbacks that implement no crypto: `get_random2b` fills the
//! nonce and counts its calls, and every other callback fails. Enough to show
//! which backend ESYS used.
use std::{
    ffi::c_void,
    sync::atomic::{AtomicUsize, Ordering},
};
use tss_esapi::{
    constants::tss::{TSS2_BASE_RC_GENERAL_FAILURE, TSS2_ESYS_RC_LAYER, TSS2_RC_SUCCESS},
    tss2_esys::{
        BYTE, ESYS_CRYPTO_CALLBACKS, ESYS_CRYPTO_CONTEXT_BLOB, TPM2_ALG_ID, TPM2B_ECC_PARAMETER,
        TPM2B_NONCE, TPM2B_PUBLIC, TPMI_AES_KEY_BITS, TPMS_ECC_POINT, TSS2_RC, size_t,
    },
};

const FAILURE: TSS2_RC = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_GENERAL_FAILURE;

/// Callbacks whose `get_random2b` increments `random_calls`.
pub fn stub_callbacks(random_calls: &'static AtomicUsize) -> ESYS_CRYPTO_CALLBACKS {
    ESYS_CRYPTO_CALLBACKS {
        rsa_pk_encrypt: Some(rsa_pk_encrypt),
        hash_start: Some(hash_start),
        hash_update: Some(hash_update),
        hash_finish: Some(hash_finish),
        hash_abort: Some(hash_abort),
        hmac_start: Some(hmac_start),
        hmac_update: Some(hash_update),
        hmac_finish: Some(hash_finish),
        hmac_abort: Some(hash_abort),
        get_random2b: Some(get_random2b),
        get_ecdh_point: Some(get_ecdh_point),
        aes_encrypt: Some(aes),
        aes_decrypt: Some(aes),
        sm4_encrypt: None,
        sm4_decrypt: None,
        init: None,
        userdata: random_calls as *const AtomicUsize as *mut c_void,
    }
}

unsafe extern "C" fn get_random2b(
    nonce: *mut TPM2B_NONCE,
    num_bytes: size_t,
    userdata: *mut c_void,
) -> TSS2_RC {
    // SAFETY: `userdata` is the `&'static AtomicUsize` set by `stub_callbacks`,
    // and ESYS passes a valid nonce.
    let (random_calls, nonce) = unsafe { (&*(userdata as *const AtomicUsize), &mut *nonce) };
    let _ = random_calls.fetch_add(1, Ordering::SeqCst);
    let len = num_bytes as usize;
    if len > nonce.buffer.len() {
        return FAILURE;
    }
    nonce.buffer[..len].fill(0xa5);
    nonce.size = len as u16;
    TSS2_RC_SUCCESS
}

unsafe extern "C" fn rsa_pk_encrypt(
    _: *mut TPM2B_PUBLIC,
    _: size_t,
    _: *mut BYTE,
    _: size_t,
    _: *mut BYTE,
    _: *mut size_t,
    _: *const std::os::raw::c_char,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn hash_start(
    _: *mut *mut ESYS_CRYPTO_CONTEXT_BLOB,
    _: TPM2_ALG_ID,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn hmac_start(
    _: *mut *mut ESYS_CRYPTO_CONTEXT_BLOB,
    _: TPM2_ALG_ID,
    _: *const u8,
    _: size_t,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn hash_update(
    _: *mut ESYS_CRYPTO_CONTEXT_BLOB,
    _: *const u8,
    _: size_t,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn hash_finish(
    _: *mut *mut ESYS_CRYPTO_CONTEXT_BLOB,
    _: *mut u8,
    _: *mut size_t,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn hash_abort(_: *mut *mut ESYS_CRYPTO_CONTEXT_BLOB, _: *mut c_void) {}

unsafe extern "C" fn get_ecdh_point(
    _: *mut TPM2B_PUBLIC,
    _: size_t,
    _: *mut TPM2B_ECC_PARAMETER,
    _: *mut TPMS_ECC_POINT,
    _: *mut BYTE,
    _: *mut size_t,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}

unsafe extern "C" fn aes(
    _: *mut u8,
    _: TPM2_ALG_ID,
    _: TPMI_AES_KEY_BITS,
    _: TPM2_ALG_ID,
    _: *mut u8,
    _: size_t,
    _: *mut u8,
    _: *mut c_void,
) -> TSS2_RC {
    FAILURE
}
