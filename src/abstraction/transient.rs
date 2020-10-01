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
use crate::constants::types::session::SessionType;
use crate::handles::KeyHandle;
use crate::structures::{Auth, Data, Digest, PublicKeyRSA, VerifiedTicket};
use crate::tcti::Tcti;
use crate::tss2_esys::*;
use crate::utils::{
    self, create_restricted_decryption_rsa_public,
    create_unrestricted_encryption_decryption_rsa_public, create_unrestricted_signing_ecc_public,
    create_unrestricted_signing_rsa_public, AsymSchemeUnion, Hierarchy, ObjectAttributes,
    PublicIdUnion, PublicKey, PublicParmsUnion, Tpm2BPublicBuilder, TpmaSessionBuilder,
    TpmsContext, TpmsRsaParmsBuilder, RSA_KEY_SIZES,
};
use crate::Context;
use crate::{Error, Result, WrapperErrorKind as ErrorKind};
use log::error;
use std::convert::{TryFrom, TryInto};

#[derive(Copy, Clone, Debug)]
pub struct RsaExponent {
    value: u32,
}

impl Default for RsaExponent {
    fn default() -> RsaExponent {
        RsaExponent {
            value: (1 << 16) + 1,
        }
    }
}

impl RsaExponent {
    pub fn new(value: u32) -> RsaExponent {
        RsaExponent { value }
    }

    pub fn value(&self) -> u32 {
        self.value
    }
}

/// Structure offering an abstracted programming experience.
///
/// The `TransientKeyContext` makes use of a root key from which the other, client-controlled
/// keyes are derived.
///
/// Currently, only functionality necessary for RSA key creation and usage (for signing,
/// verifying signatures, encryption and decryption) is implemented. The RSA SSA
/// asymmetric scheme with SHA256 is used for all created and imported signing keys.
/// The RSA OAEP asymmetric scheme with SHA256 is used for all created and imported
/// signing/encryption/decryption keys.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct TransientKeyContext {
    context: Context,
    root_key_handle: KeyHandle,
}

impl TransientKeyContext {
    /// Create a new key.
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
    /// * if the key_params is not for an RSA key, `InvalidParam` is returned
    /// * if the key_params does not have an `AnySig` scheme, `InvalidParam` is returned
    /// * errors are returned if any method calls return an error: `Context::get_random`,
    /// `TransientKeyContext::set_session_attrs`, `Context::create_key`, `Context::load`,
    /// `Context::context_save`, `Context::context_flush`
    pub fn create_key(
        &mut self,
        key_params: KeyParams,
        auth_size: usize,
    ) -> Result<(TpmsContext, Option<Auth>)> {
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
            &self.get_public_from_params(key_params)?,
            key_auth.as_ref(),
            None,
            None,
            &[],
        )?;
        self.set_session_attrs()?;
        let key_handle = self.context.load(self.root_key_handle, key_priv, key_pub)?;

        self.set_session_attrs()?;
        let key_context = self.context.context_save(key_handle.into()).or_else(|e| {
            self.context.flush_context(key_handle.into())?;
            Err(e)
        })?;
        self.context.flush_context(key_handle.into())?;
        Ok((key_context, key_auth))
    }

    fn get_public_from_params(&self, params: KeyParams) -> Result<TPM2B_PUBLIC> {
        match params {
            KeyParams::RsaSign {
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
            KeyParams::RsaEncrypt { size, pub_exponent } => {
                if RSA_KEY_SIZES.iter().find(|sz| **sz == size).is_none() {
                    return Err(Error::local_error(ErrorKind::WrongParamSize));
                }
                create_unrestricted_encryption_decryption_rsa_public(size, pub_exponent)
            }
            KeyParams::Ecc { curve, scheme } => {
                Ok(create_unrestricted_signing_ecc_public(scheme, curve)?)
            }
        }
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
    /// `TransientKeyContext::`set_session_attrs`, `Context::load_external_public`,
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
        let key_context = self.context.context_save(key_handle.into()).or_else(|e| {
            self.context.flush_context(key_handle.into())?;
            Err(e)
        })?;
        self.context.flush_context(key_handle.into())?;
        Ok(key_context)
    }

    /// Load a previously generated RSA keypair. Currently only supports signing keys for RSA PKCS 1v5 with SHA256.
    ///
    /// Returns the key context.
    ///
    /// # Constraints
    /// * `public_modulus` must be 128, 256, 384 or 512 bytes (i.e. slice elements) long, corresponding to
    ///   1024, 2048, 3072 or 4096 bits
    /// * `key_prime`'s length must coincide with that of the public key. Namely, `key_prime` should
    ///   be 64, 128, 192, or 256 bytes (i.e. slice elements) long for public keys of length 128, 256,
    ///   384 or 512 respectively (which in turn correspond to 512/1024/1536/2048 bits for
    ///   `key_prime`).
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error.
    /// `TransientKeyContext::`set_session_attrs`, `Context::load_external`,
    /// `Context::context_save`, `Context::flush_context`
    pub fn load_external_rsa(
        &mut self,
        key_prime: &[u8],
        public_modulus: &[u8],
        public_exponent: RsaExponent,
    ) -> Result<TpmsContext> {
        if RSA_KEY_SIZES
            .iter()
            .find(|sz| usize::from(**sz) == public_modulus.len() * 8)
            .is_none()
        {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }

        // Check if there is a mismatch between private key and public key sizes.
        if key_prime.len() * 2 != public_modulus.len() {
            return Err(Error::local_error(ErrorKind::WrongParamSize));
        }

        // Handle public key...
        let mut public_modulus_buffer = [0_u8; 512];
        public_modulus_buffer[..public_modulus.len()]
            .clone_from_slice(&public_modulus[..public_modulus.len()]);

        let pub_buffer = TPM2B_PUBLIC_KEY_RSA {
            size: public_modulus.len().try_into().unwrap(),
            buffer: public_modulus_buffer,
        };
        let pub_id_union = PublicIdUnion::Rsa(Box::from(pub_buffer));

        let mut object_attributes = ObjectAttributes(0);
        object_attributes.set_user_with_auth(true);
        object_attributes.set_decrypt(false);
        object_attributes.set_sign_encrypt(true);
        object_attributes.set_restricted(false);

        let rsa_parms = TpmsRsaParmsBuilder::new_unrestricted_signing_key(
            AsymSchemeUnion::RSASSA(HashingAlgorithm::Sha256),
            u16::try_from(public_modulus.len()).unwrap() * 8_u16,
            public_exponent.value(),
        )
        .build()
        .unwrap();

        let public = Tpm2BPublicBuilder::new()
            .with_type(TPM2_ALG_RSA)
            .with_name_alg(TPM2_ALG_SHA256)
            .with_object_attributes(object_attributes)
            .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
            .with_unique(pub_id_union)
            .build()
            .unwrap();

        // Handle private key...
        let mut key_prime_buffer = [0_u8; 256];
        key_prime_buffer[..key_prime.len()].clone_from_slice(&key_prime[..key_prime.len()]);

        let key_prime_len = key_prime.len().try_into().unwrap(); // should not fail on valid targets, given the checks above
        let private = TPM2B_SENSITIVE {
            size: key_prime_len,
            sensitiveArea: TPMT_SENSITIVE {
                sensitiveType: TPM2_ALG_RSA,
                authValue: Default::default(),
                seedValue: Default::default(),
                sensitive: TPMU_SENSITIVE_COMPOSITE {
                    rsa: TPM2B_PRIVATE_KEY_RSA {
                        size: key_prime_len,
                        buffer: key_prime_buffer,
                    },
                },
            },
        };
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .load_external(&private, &public, Hierarchy::Null)?;
        self.set_session_attrs()?;
        let key_context = self.context.context_save(key_handle.into()).or_else(|e| {
            self.context.flush_context(key_handle.into())?;
            Err(e)
        })?;
        self.context.flush_context(key_handle.into())?;
        Ok(key_context)
    }

    /// Read the public part from a previously generated key.
    ///
    /// The method takes the key as a parameter and returns its public part.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::read_public`, `Context::flush_context`,
    /// `TransientKeyContext::set_session_attrs`
    pub fn read_public_key(&mut self, key_context: TpmsContext) -> Result<PublicKey> {
        self.set_session_attrs()?;
        let key_handle = self.context.context_load(key_context)?;

        self.set_session_attrs()?;
        let key_pub_id = self.context.read_public(key_handle.into()).or_else(|e| {
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

    /// Encrypt a message with an existing key.
    ///
    /// Takes the key as a parameter, encrypts the message and returns the ciphertext. A label (i.e.
    /// nonce) can also be provided.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::rsa_encrypt`, `Context::flush_context`, `TransientKeyContext::set_session_attrs`
    /// `Context::set_handle_auth`
    pub fn rsa_encrypt(
        &mut self,
        key_context: TpmsContext,
        key_auth: Option<Auth>,
        message: PublicKeyRSA,
        scheme: AsymSchemeUnion,
        label: Option<Data>,
    ) -> Result<PublicKeyRSA> {
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .context_load(key_context)
            .map(KeyHandle::from)?;
        if let Some(key_auth_value) = key_auth {
            self.context
                .tr_set_auth(key_handle.into(), &key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle.into())?;
                    Err(e)
                })?;
        }
        let scheme = scheme.get_rsa_decrypt_struct();
        self.set_session_attrs()?;

        let ciphertext = self
            .context
            .rsa_encrypt(key_handle, message, &scheme, label.unwrap_or_default())
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;

        self.context.flush_context(key_handle.into())?;

        Ok(ciphertext)
    }

    /// Decrypt ciphertext with an existing key.
    ///
    /// Takes the key as a parameter, decrypts the ciphertext and returns the plaintext. A label (i.e.
    /// nonce) can also be provided.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::rsa_decrypt`, `Context::flush_context`, `TransientKeyContext::set_session_attrs`
    /// `Context::set_handle_auth`
    pub fn rsa_decrypt(
        &mut self,
        key_context: TpmsContext,
        key_auth: Option<Auth>,
        ciphertext: PublicKeyRSA,
        scheme: AsymSchemeUnion,
        label: Option<Data>,
    ) -> Result<PublicKeyRSA> {
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .context_load(key_context)
            .map(KeyHandle::from)?;
        if let Some(key_auth_value) = key_auth {
            self.context
                .tr_set_auth(key_handle.into(), &key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle.into())?;
                    Err(e)
                })?;
        }
        let scheme = scheme.get_rsa_decrypt_struct();
        self.set_session_attrs()?;

        let plaintext = self
            .context
            .rsa_decrypt(key_handle, ciphertext, &scheme, label.unwrap_or_default())
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;

        self.context.flush_context(key_handle.into())?;

        Ok(plaintext)
    }

    /// Sign a digest with an existing key.
    ///
    /// Takes the key as a parameter, signs and returns the signature.
    ///
    /// # Errors
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::sign`, `Context::flush_context`, `TransientKeyContext::set_session_attrs`
    /// `Context::set_handle_auth`
    pub fn sign(
        &mut self,
        key_context: TpmsContext,
        key_auth: Option<Auth>,
        digest: Digest,
    ) -> Result<utils::Signature> {
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .context_load(key_context)
            .map(KeyHandle::from)?;
        if let Some(key_auth_value) = key_auth {
            self.context
                .tr_set_auth(key_handle.into(), &key_auth_value)
                .or_else(|e| {
                    self.context.flush_context(key_handle.into())?;
                    Err(e)
                })?;
        }
        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        self.set_session_attrs()?;
        let signature = self
            .context
            .sign(key_handle, &digest, scheme, &validation)
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(key_handle.into())?;
        Ok(signature)
    }

    /// Verify a signature against a digest.
    ///
    /// Given a digest, a key and a signature, this method returns a `Verified` ticket if the
    /// verification was successful.
    ///
    /// # Errors
    /// * if the verification fails (i.e. the signature is invalid), a TPM error is returned
    /// * errors are returned if any method calls return an error: `Context::context_load`,
    /// `Context::verify_signature`, `Context::flush_context`,
    /// `TransientKeyContext::set_session_attrs`
    pub fn verify_signature(
        &mut self,
        key_context: TpmsContext,
        digest: Digest,
        signature: utils::Signature,
    ) -> Result<VerifiedTicket> {
        self.set_session_attrs()?;
        let key_handle = self
            .context
            .context_load(key_context)
            .map(KeyHandle::from)?;

        let signature: TPMT_SIGNATURE = signature.try_into().or_else(|e| {
            self.context.flush_context(key_handle.into())?;
            Err(e)
        })?;
        self.set_session_attrs()?;
        let verified = self
            .context
            .verify_signature(key_handle, &digest, &signature)
            .or_else(|e| {
                self.context.flush_context(key_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(key_handle.into())?;
        Ok(verified.try_into()?)
    }

    /// Sets the encrypt and decrypt flags on the main session used by the context.
    ///
    /// # Errors
    /// * if `Context::set_session_attr` returns an error, that error is propagated through
    fn set_session_attrs(&mut self) -> Result<()> {
        if let (Some(session), _, _) = self.context.sessions() {
            let session_attr = utils::TpmaSessionBuilder::new()
                .with_flag(TPMA_SESSION_DECRYPT)
                .with_flag(TPMA_SESSION_ENCRYPT)
                .build();
            self.context.tr_sess_set_attributes(session, session_attr)?;
        }
        Ok(())
    }
}

/// Build a new `TransientKeyContext`.
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
pub struct TransientKeyContextBuilder {
    tcti: Tcti,
    hierarchy: Hierarchy,
    root_key_size: u16, // TODO: replace with root key PUBLIC definition
    root_key_auth_size: usize,
    hierarchy_auth: Vec<u8>,
    default_context_cipher: Cipher,
    session_hash_alg: HashingAlgorithm,
}

impl TransientKeyContextBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        TransientKeyContextBuilder {
            tcti: Tcti::Device(Default::default()),
            hierarchy: Hierarchy::Owner,
            root_key_size: 2048,
            root_key_auth_size: 32,
            hierarchy_auth: Vec::new(),
            default_context_cipher: Cipher::aes_256_cfb(),
            session_hash_alg: HashingAlgorithm::Sha256,
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
    pub fn with_session_hash_alg(mut self, session_hash_alg: HashingAlgorithm) -> Self {
        self.session_hash_alg = session_hash_alg;
        self
    }

    /// Bootstrap the TransientKeyContext.
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
    pub unsafe fn build(self) -> Result<TransientKeyContext> {
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

        let session = context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Hmac,
                self.default_context_cipher,
                self.session_hash_alg,
            )
            .and_then(|session| {
                session.ok_or_else(|| {
                    error!("Received unexpected NONE handle from the TPM");
                    Error::local_error(ErrorKind::WrongValueFromTpm)
                })
            })?;

        let session_attr = TpmaSessionBuilder::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT)
            .build();
        context.tr_sess_set_attributes(session, session_attr)?;

        context.set_sessions((Some(session), None, None));
        let root_key_auth = if self.root_key_auth_size > 0 {
            let random = context.get_random(self.root_key_auth_size)?;
            Some(Auth::try_from(random.value().to_vec())?)
        } else {
            None
        };

        if !self.hierarchy_auth.is_empty() {
            let auth_hierarchy = Auth::try_from(self.hierarchy_auth)?;
            context.tr_set_auth(self.hierarchy.esys_rh().into(), &auth_hierarchy)?;
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

        let new_session = context
            .start_auth_session(
                Some(root_key_handle),
                None,
                None,
                SessionType::Hmac,
                self.default_context_cipher,
                self.session_hash_alg,
            )
            .and_then(|session| {
                session.ok_or_else(|| {
                    error!("Received unexpected NONE handle from the TPM");
                    Error::local_error(ErrorKind::WrongValueFromTpm)
                })
            })?;
        if let (Some(old_session), _, _) = context.sessions() {
            context.set_sessions((Some(new_session), None, None));
            context.flush_context(old_session.handle().into())?;
        }
        Ok(TransientKeyContext {
            context,
            root_key_handle,
        })
    }
}

impl Default for TransientKeyContextBuilder {
    fn default() -> Self {
        TransientKeyContextBuilder::new()
    }
}

/// Parameters for the kinds of keys supported by the context
#[derive(Debug, Clone, Copy)]
pub enum KeyParams {
    RsaSign {
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
    RsaEncrypt {
        /// Size of key in bits
        ///
        /// Can only be one of: 1024, 2048, 3072 or 4096
        size: u16,
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
