// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Error, Result, ReturnCode, WrapperErrorKind,
    tss2_esys::{ESYS_CRYPTO_CALLBACKS, Esys_SetCryptoCallbacks},
};
use log::error;
use std::sync::OnceLock;

/// The process-wide default, applied by [`Context::new`].
struct DefaultCryptoCallbacks(ESYS_CRYPTO_CALLBACKS);

// SAFETY: `set_default_crypto_callbacks` requires the callbacks and their
// `userdata` to be usable from any thread.
unsafe impl Send for DefaultCryptoCallbacks {}
unsafe impl Sync for DefaultCryptoCallbacks {}

static DEFAULT_CRYPTO_CALLBACKS: OnceLock<DefaultCryptoCallbacks> = OnceLock::new();

impl Context {
    /// Replaces the crypto backend ESYS uses for this context: session HMACs and
    /// key derivation, parameter encryption, salt encryption, nonces and object
    /// names.
    ///
    /// Required when tpm2-tss is built without a crypto library
    /// (`--with-crypto=none`), unless [`Context::set_default_crypto_callbacks`]
    /// was called: until then, every ESYS operation that needs host-side crypto
    /// fails with `TSS2_ESYS_RC_CALLBACK_NULL`. On a tpm2-tss built with OpenSSL
    /// or mbedTLS it overrides that library for this context.
    ///
    /// All callbacks are required except `init`, `sm4_encrypt` and `sm4_decrypt`.
    /// ESYS copies `callbacks`, so it only needs to live for the call.
    ///
    /// # Safety
    /// Each callback must implement the contract documented for its type in
    /// `tss2_esys.h`, and `callbacks.userdata` must remain valid for as long as this
    /// context exists.
    ///
    /// # Errors
    /// * `TSS2_ESYS_RC_CALLBACK_NULL` if a required callback is missing.
    pub unsafe fn set_crypto_callbacks(&mut self, callbacks: &ESYS_CRYPTO_CALLBACKS) -> Result<()> {
        let mut callbacks = *callbacks;
        ReturnCode::ensure_success(
            unsafe { Esys_SetCryptoCallbacks(self.mut_context(), &mut callbacks) },
            |ret| {
                error!("Error when setting crypto callbacks: {:#010X}", ret);
            },
        )
    }

    /// Sets the crypto callbacks every [`Context`] created afterwards starts
    /// with, in the manner of rustls' `CryptoProvider::install_default`. Covers
    /// contexts this crate creates internally, such as `TransientKeyContext`'s.
    /// Contexts that already exist are unaffected, and
    /// [`Context::set_crypto_callbacks`] still overrides it per context.
    ///
    /// # Safety
    /// As for [`Context::set_crypto_callbacks`], and additionally the callbacks
    /// and `callbacks.userdata` must be usable from any thread for the rest of
    /// the process.
    ///
    /// # Errors
    /// * [`WrapperErrorKind::InvalidParam`] if a default was already set.
    pub unsafe fn set_default_crypto_callbacks(callbacks: &ESYS_CRYPTO_CALLBACKS) -> Result<()> {
        DEFAULT_CRYPTO_CALLBACKS
            .set(DefaultCryptoCallbacks(*callbacks))
            .map_err(|_| {
                error!("Default crypto callbacks are already set");
                Error::local_error(WrapperErrorKind::InvalidParam)
            })
    }

    pub(crate) fn apply_default_crypto_callbacks(&mut self) -> Result<()> {
        match DEFAULT_CRYPTO_CALLBACKS.get() {
            // SAFETY: guaranteed by the caller of `set_default_crypto_callbacks`.
            Some(default) => unsafe { self.set_crypto_callbacks(&default.0) },
            None => Ok(()),
        }
    }
}
