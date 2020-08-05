// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Module for abstracting resource handle management
//!
//! This module presents an abstraction over the TPM functionality exposed through the core
//! `Context` structure. The abstraction works by hiding resource handle management from the
//! client. This is achieved by passing objects back and forth in the form of contexts. Thus, when
//! an object is created, its saved context is returned and the object is flushed from the TPM.
//! Whenever the client needs to use said object, it calls the desired operation with the context
//! as a parameter - the context is loaded in the TPM, the operation performed and the context
//! flushed out again before the result is returned.
//!
//! Object contexts thus act as an opaque handle that can, however, be used by the client to seralize
//! and persist the underlying data.
use crate::constants::algorithm::{Cipher, EllipticCurve, HashingAlgorithm};
use crate::constants::tss::*;
use crate::structures::{Auth, Data, Digest, MaxBuffer, PcrSelectionList, VerifiedTicket};
use crate::tcti::Tcti;
use crate::tss2_esys::*;
use crate::utils::{
    self, create_restricted_decryption_rsa_public, create_unrestricted_signing_ecc_public,
    create_unrestricted_signing_rsa_public, AsymSchemeUnion, Hierarchy, PublicIdUnion, PublicKey,
    TpmaSessionBuilder, TpmsContext, RSA_KEY_SIZES,
};
use crate::Context;
use crate::{Error, Result, WrapperErrorKind as ErrorKind};
use log::error;
use std::convert::{TryFrom, TryInto};

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

/// Structure offering an abstracted programming experience.
///
/// The `QuoteContext` makes use of a root key from which the other, client-controlled
/// keyes are derived.
///
/// Currently, only functionality necessary for RSA key creation and usage (for signing and
/// verifying signatures) is implemented. More precisely, the RSA SSA asymmetric scheme with
/// SHA256 is used for all created and imported keys.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct QuoteContext {
    context: Context,
    root_key_handle: ESYS_TR,
}

impl QuoteContext {
    /// Create a new signing key.
    ///
    /// A key is created as a descendant of the context root key, with the given parameters.
    ///
    /// If successful, the result contains the saved context of the key and a vector of
    /// bytes forming the authentication value for said key.
    ///
    /// # Constraints
    /// * `auth_size` must be at most 32
    ///
    /// # Errors
    /// * if the authentication size is larger than 32 a `WrongParamSize` wrapper error is returned
    /// * for RSA keys, if the specified key size is not one of 1024, 2048, 3072 or 4096, `WrongParamSize`
    /// is returned
    /// * if the asymmetric scheme is not a signing scheme, `InconsistentParams` is returned
    /// * errors are returned if any method calls return an error: `Context::get_random`,
    /// `QuoteContext::set_session_attrs`, `Context::create_key`, `Context::flush_context`
    pub fn create_key(
        &mut self,
        key_params: KeyParams,
        auth_size: usize,
    ) -> Result<(Option<Auth>, TPM2B_PRIVATE, TPM2B_PUBLIC)> {
        if auth_size > 32 {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        let key_auth = if auth_size > 0 {
            self.set_session_attrs()?;
            let random_bytes = self.context.get_random(auth_size)?;
            Some(Auth::try_from(random_bytes.value().to_vec())?)
        } else {
            None
        };

        self.set_session_attrs()?;
        let (key_priv, key_pub) = self.context.create_key(
            self.root_key_handle,
            &key_params.get_public_from_params()?,
            key_auth.as_ref(),
            None,
            None,
            &[],
        )?;

        self.set_session_attrs()?;
        Ok((key_auth, key_priv, key_pub))
    }

    /// Load a previously generated key again.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error:
    /// `QuoteContext::set_session_attrs`, `Context::load`,
    /// `Context::context_save`, `Context::flush_context`
    pub fn load_key(
        &mut self,
        key_priv: TPM2B_PRIVATE,
        key_pub: TPM2B_PUBLIC,
    ) -> Result<TpmsContext> {
        self.set_session_attrs()?;
        let key_handle = self.context.load(self.root_key_handle, key_priv, key_pub)?;

        self.set_session_attrs()?;
        let key_context = self.context.context_save(key_handle).or_else(|e| {
            self.context.flush_context(key_handle)?;
            Err(e)
        })?;
        self.context.flush_context(key_handle)?;
        Ok(key_context)
    }

    /// load existing rsa key from file or create new keys, if file not exists
    ///
    ///
    pub fn load_or_create_rsa_key(
        &mut self,
        path: String,
        key_params: KeyParams,
    ) -> Result<TpmsContext> {
        let path = Path::new(&path);

        // create keys and store them in file
        if !path.exists() {
            let (_, private, public) = self.create_key(key_params, 0)?;

            let private_data = &private.buffer[..private.size as usize];
            let mut data = hex::encode_upper(private_data).into_bytes();
            data.push(b'\n');

            let public_data = match unsafe { PublicIdUnion::from_public(&public)? } {
                PublicIdUnion::Rsa(pub_key) => pub_key.buffer[..pub_key.size as usize].to_vec(),
                _ => return Err(Error::local_error(ErrorKind::UnsupportedParam)),
            };
            data.append(&mut hex::encode_upper(public_data.as_slice()).into_bytes());

            let mut file = File::create(path).unwrap();
            file.write_all(&data[..]).unwrap();

            return self.load_key(private, public);
        }
        // read keys from file
        let mut file = File::open(path).unwrap();

        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return Err(Error::local_error(ErrorKind::InvalidParam));
        }

        let mut lines = contents.lines();

        let private = lines.next().unwrap().as_bytes();
        let public = lines.next().unwrap().as_bytes();

        self.load_rsa_key(
            hex::decode(private).unwrap().as_slice(),
            hex::decode(public).unwrap().as_slice(),
        )
    }

    /// Load a previously generated RSA key again.
    ///
    /// Returns the key context.
    ///
    /// # Constraints
    /// * `public_key` must be 128, 256, 384 or 512 bytes (i.e. slice elements) long, corresponding to 1024, 2048, 3072 or 4096 bits
    /// * if the public key length is different than 128, 256, 384 or 512 bytes, a `WrongParamSize` wrapper error is returned
    /// * errors are returned if any method calls return an error:
    pub fn load_rsa_key(&mut self, private_key: &[u8], public_key: &[u8]) -> Result<TpmsContext> {
        if RSA_KEY_SIZES
            .iter()
            .find(|sz| usize::from(**sz) == public_key.len() * 8)
            .is_none()
        {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        let mut pk_buffer = [0_u8; 512];
        pk_buffer[..public_key.len()].clone_from_slice(&public_key[..public_key.len()]);
        let pk = TPMU_PUBLIC_ID {
            rsa: TPM2B_PUBLIC_KEY_RSA {
                size: public_key.len().try_into().unwrap(), // should not fail on valid targets, given the checks above
                buffer: pk_buffer,
            },
        };
        let mut public = create_unrestricted_signing_rsa_public(
            AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            u16::try_from(public_key.len()).unwrap() * 8_u16,
            0,
        )?;
        public.publicArea.unique = pk;

        let mut pk_buffer = [0_u8; 1550];
        pk_buffer[..private_key.len()].clone_from_slice(&private_key[..private_key.len()]);
        let private = TPM2B_PRIVATE {
            size: private_key.len().try_into().unwrap(), // should not fail on valid targets, given the checks above
            buffer: pk_buffer,
        };
        self.load_key(private, public)
    }

    /// Load a previously generated RSA public key.
    ///
    /// Returns the key context.
    ///
    /// # Constraints
    /// * `public_key` must be 128, 256, 384 or 512 bytes (i.e. slice elements) long, corresponding to 1024, 2048, 3072 or 4096 bits
    ///
    /// # Errors
    /// * if the public key length is different than 128, 256, 384 or 512 bytes, a `WrongParamSize` wrapper error is returned
    /// * errors are returned if any method calls return an error:
    /// `QuoteContext::`set_session_attrs`, `Context::load_external_public`,
    /// `Context::context_save`, `Context::flush_context`
    pub fn load_external_rsa_public_key(&mut self, public_key: &[u8]) -> Result<TpmsContext> {
        if RSA_KEY_SIZES
            .iter()
            .find(|sz| usize::from(**sz) == public_key.len() * 8)
            .is_none()
        {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        let mut pk_buffer = [0_u8; 512];
        pk_buffer[..public_key.len()].clone_from_slice(&public_key[..public_key.len()]);
        let pk = TPMU_PUBLIC_ID {
            rsa: TPM2B_PUBLIC_KEY_RSA {
                size: public_key.len().try_into().unwrap(), // should not fail on valid targets, given the checks above
                buffer: pk_buffer,
            },
        };
        let mut public = create_unrestricted_signing_rsa_public(
            AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            u16::try_from(public_key.len()).unwrap() * 8_u16,
            0,
        )?;
        public.publicArea.unique = pk;
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .load_external_public(&public, Hierarchy::Owner)?;
        self.set_session_attrs()?;
        let key_context = self.context.context_save(key_handle).or_else(|e| {
            self.context.flush_context(key_handle)?;
            Err(e)
        })?;
        self.context.flush_context(key_handle)?;
        Ok(key_context)
    }

    /// Read the public part from a previously generated key.
    ///
    /// The method takes the key as a parameter and returns its public part.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::read_public`, `Context::flush_context`,
    /// `QuoteContext::set_session_attrs`
    pub fn read_public_key(&mut self, key_context: TpmsContext) -> Result<PublicKey> {
        self.set_session_attrs()?;
        let key_handle = self.context.context_load(key_context)?;

        self.set_session_attrs()?;
        let key_pub_id = self.context.read_public(key_handle).or_else(|e| {
            self.context.flush_context(key_handle)?;
            Err(e)
        })?;
        let key = match unsafe { PublicIdUnion::from_public(&key_pub_id)? } {
            // call should be safe given our trust in the TSS library
            PublicIdUnion::Rsa(pub_key) => {
                let mut key = pub_key.buffer.to_vec();
                key.truncate(pub_key.size.try_into().unwrap()); // should not fail on supported targets
                PublicKey::Rsa(key)
            }
            PublicIdUnion::Ecc(pub_key) => {
                let mut x = pub_key.x.buffer.to_vec();
                x.truncate(pub_key.x.size.try_into().unwrap()); // should not fail on supported targets
                let mut y = pub_key.y.buffer.to_vec();
                y.truncate(pub_key.y.size.try_into().unwrap()); // should not fail on supported targets
                PublicKey::Ecc { x, y }
            }
            _ => return Err(Error::local_error(ErrorKind::UnsupportedParam)),
        };
        self.context.flush_context(key_handle)?;

        Ok(key)
    }

    /// Create Quote with given PCR selection.
    ///
    /// Given PCR Selection and qualifying data quote it and return attested data and signature.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::quote`, `Context::flush_context`, `QuoteContext::set_session_attrs`
    /// `Context::set_handle_auth`
    pub fn quote(
        &mut self,
        key_context: TpmsContext,
        key_auth: Option<Auth>,
        qualifying_data: Data,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<(TPM2B_ATTEST, utils::Signature)> {
        self.set_session_attrs()?;
        let key_handle = self.context.context_load(key_context)?;
        if let Some(key_auth_value) = key_auth {
            self.context
                .tr_set_auth(key_handle, &key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle)?;
                    Err(e)
                })?;
        }

        let signing_scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };

        self.set_session_attrs()?;
        let ret = self
            .context
            .quote(
                key_handle,
                &qualifying_data,
                signing_scheme,
                pcr_selection_list,
            )
            .or_else(|e| {
                self.context.flush_context(key_handle)?;
                Err(e)
            })?;
        self.context.flush_context(key_handle)?;
        Ok(ret)
    }

    /// Verify Quote by given Signature
    ///
    /// # Errors
    /// * if the verification fails (i.e. the signature is invalid), a TPM error is returned
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::hash`, `Context::verify_signature`, `Context::flush_context`,
    /// `QuoteContext::set_session_attrs`
    pub fn verify_quote_signature(
        &mut self,
        key_context: TpmsContext,
        attest: TPM2B_ATTEST,
        signature: utils::Signature,
    ) -> Result<VerifiedTicket> {
        let mut data = attest.attestationData.to_vec();
        data.truncate(attest.size.try_into().unwrap()); // should not fail on supported targets
        let max_buffer: MaxBuffer = data.try_into().unwrap();

        let digest = self
            .context
            .hash(&max_buffer, HashingAlgorithm::Sha256, Hierarchy::Null)?;
        let digest_workaround: Digest = digest.0;

        self.set_session_attrs()?;
        let key_handle = self.context.context_load(key_context)?;

        let signature: TPMT_SIGNATURE = signature.try_into().or_else(|e| {
            self.context.flush_context(key_handle)?;
            Err(e)
        })?;
        self.set_session_attrs()?;
        let verified = self
            .context
            .verify_signature(key_handle, &digest_workaround, &signature)
            .or_else(|e| {
                self.context.flush_context(key_handle)?;
                Err(e)
            })?;
        self.context.flush_context(key_handle)?;
        Ok(verified.try_into()?)
    }

    /// Sets the encrypt and decrypt flags on the main session used by the context.
    ///
    /// # Errors
    /// * if `Context::set_session_attr` returns an error, that error is propagated through
    fn set_session_attrs(&mut self) -> Result<()> {
        let (session, _, _) = self.context.sessions();
        let session_attr = utils::TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        self.context.tr_sess_set_attributes(session, session_attr)?;
        Ok(())
    }
}

/// Build a new `QuoteContext`.
///
/// # Default values
/// * TCTI: Device TCTI
/// * Hierarchy: Owner hierarchy
/// * Root key size: 2048 bits
/// * Root key authentication size: 32 bytes
/// * Hierarchy authentication value: Empty array of bytes
/// * Session encryption cipher: 256 bit AES in CFB mode
/// * Session hash algorithm: SHA256
#[derive(Debug)]
pub struct QuoteContextBuilder {
    tcti: Tcti,
    hierarchy: Hierarchy,
    root_key_size: u16, // TODO: replace with root key PUBLIC definition
    root_key_auth_size: usize,
    hierarchy_auth: Vec<u8>,
    default_context_cipher: Cipher,
    session_hash_alg: TPM2_ALG_ID, // TODO: Create Rust-native version
}

impl QuoteContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        QuoteContextBuilder {
            tcti: Tcti::Device(Default::default()),
            hierarchy: Hierarchy::Owner,
            root_key_size: 2048,
            root_key_auth_size: 32,
            hierarchy_auth: Vec::new(),
            default_context_cipher: Cipher::aes_256_cfb(),
            session_hash_alg: TPM2_ALG_SHA256,
        }
    }

    /// Define the TCTI to be used by the client.
    pub fn with_tcti(mut self, tcti: Tcti) -> Self {
        self.tcti = tcti;
        self
    }

    /// Define which hierarchy will be used for the keys being managed.
    pub fn with_hierarchy(mut self, hierarchy: Hierarchy) -> Self {
        self.hierarchy = hierarchy;
        self
    }

    /// Choose length in bits of primary key that will serve as parent to all user keys.
    pub fn with_root_key_size(mut self, root_key_size: u16) -> Self {
        self.root_key_size = root_key_size;
        self
    }

    /// Choose authentication value length (in bytes) for primary key.
    pub fn with_root_key_auth_size(mut self, root_key_auth_size: usize) -> Self {
        self.root_key_auth_size = root_key_auth_size;
        self
    }

    /// Input the authentication value of the working hierarchy.
    pub fn with_hierarchy_auth(mut self, hierarchy_auth: Vec<u8>) -> Self {
        self.hierarchy_auth = hierarchy_auth;
        self
    }

    /// Define the cipher to be used within this context as a default.
    ///
    /// Currently this default is used for:
    /// * securing command parameters using session-based encryption
    /// * encrypting all user keys using the primary key
    pub fn with_default_context_cipher(mut self, default_context_cipher: Cipher) -> Self {
        self.default_context_cipher = default_context_cipher;
        self
    }

    /// Define the cipher to be used by sessions for hashing commands.
    pub fn with_session_hash_alg(mut self, session_hash_alg: TPM2_ALG_ID) -> Self {
        self.session_hash_alg = session_hash_alg;
        self
    }

    /// Bootstrap the QuoteContext.
    ///
    /// The root key is created as a primary key in the provided hierarchy and thus authentication is
    /// needed for said hierarchy. The authentication valuei for the key is generated by the TPM itself,
    /// with a configurable length, and never exposed outside the context.
    ///
    /// # Safety
    /// * it is the responsibility of the client to ensure that the context can be initialized
    /// safely, threading-wise
    /// * the client is also responsible of choosing the correct TCTI to connect to.
    /// * it is the responsability of the client to set a sufficiently secure default cipher for the context
    ///
    /// # Constraints
    /// * `root_key_size` must be 1024, 2048, 3072 or 4096
    /// * `root_key_auth_size` must be at most 32
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::get_random`,
    /// `Context::start_auth_session`, `Context::create_primary_key`, `Context::flush_context`,
    /// `Context::set_handle_auth`
    /// * if the root key authentication size is given greater than 32 or if the root key size is
    /// not 1024, 2048, 3072 or 4096, a `WrongParamSize` wrapper error is returned
    pub unsafe fn build(self) -> Result<QuoteContext> {
        if self.root_key_auth_size > 32 {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        if RSA_KEY_SIZES
            .iter()
            .find(|sz| **sz == self.root_key_size)
            .is_none()
        {
            error!("The reference implementation only supports key sizes of 1,024 and 2,048 bits.");
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }
        let mut context = Context::new(self.tcti)?;

        let session = context.start_auth_session(
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            None,
            TPM2_SE_HMAC,
            self.default_context_cipher.into(),
            self.session_hash_alg,
        )?;
        let session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context.tr_sess_set_attributes(session, session_attr)?;

        context.set_sessions((session, ESYS_TR_NONE, ESYS_TR_NONE));
        let root_key_auth = if self.root_key_auth_size > 0 {
            let random = context.get_random(self.root_key_auth_size)?;
            Some(Auth::try_from(random.value().to_vec())?)
        } else {
            None
        };

        if !self.hierarchy_auth.is_empty() {
            let auth_hierarchy = Auth::try_from(self.hierarchy_auth)?;
            context.tr_set_auth(self.hierarchy.esys_rh(), &auth_hierarchy)?;
        }

        let root_key_handle = context.create_primary_key(
            self.hierarchy.esys_rh(),
            &create_restricted_decryption_rsa_public(
                self.default_context_cipher,
                self.root_key_size,
                0,
            )?,
            root_key_auth.as_ref(),
            None,
            None,
            &[],
        )?;

        let new_session = context.start_auth_session(
            root_key_handle,
            ESYS_TR_NONE,
            None,
            TPM2_SE_HMAC,
            self.default_context_cipher.into(),
            self.session_hash_alg,
        )?;
        let (old_session, _, _) = context.sessions();
        context.set_sessions((new_session, ESYS_TR_NONE, ESYS_TR_NONE));
        context.flush_context(old_session)?;
        Ok(QuoteContext {
            context,
            root_key_handle,
        })
    }
}

impl Default for QuoteContextBuilder {
    fn default() -> Self {
        QuoteContextBuilder::new()
    }
}

/// Parameters for the kinds of keys supported by the context
#[derive(Debug, Clone, Copy)]
pub enum KeyParams {
    Rsa {
        /// Size of key in bits
        ///
        /// Can only be one of: 1024, 2048, 3072 or 4096
        size: u16,
        /// Asymmetric scheme to be used with the key
        ///
        /// *Must* be an RSA-specific scheme
        scheme: AsymSchemeUnion,
        /// Public exponent of the key
        ///
        /// If set to 0, it will default to 2^16 - 1
        pub_exponent: u32,
    },
    Ecc {
        /// Curve that the key will be based on
        curve: EllipticCurve,
        /// Asymmetric scheme to be used with the key
        ///
        /// *Must* be an ECC scheme
        scheme: AsymSchemeUnion,
    },
}

impl KeyParams {
    pub fn get_public_from_params(self) -> Result<TPM2B_PUBLIC> {
        match self {
            KeyParams::Rsa {
                size,
                scheme,
                pub_exponent,
            } => {
                if RSA_KEY_SIZES.iter().find(|sz| **sz == size).is_none() {
                    return Err(Error::local_error(ErrorKind::WrongParamSize));
                }

                Ok(create_unrestricted_signing_rsa_public(
                    scheme,
                    size,
                    pub_exponent,
                )?)
            }
            KeyParams::Ecc { curve, scheme } => {
                Ok(create_unrestricted_signing_ecc_public(scheme, curve)?)
            }
        }
    }
}
