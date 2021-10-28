// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use super::{ObjectWrapper, TransientKeyContext};
use crate::{
    abstraction::ek,
    constants::SessionType,
    handles::{AuthHandle, SessionHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm},
        session_handles::PolicySession,
    },
    structures::{EncryptedSecret, IDObject, SymmetricDefinition},
    tss2_esys::{TPM2B_PUBLIC, TPMT_PUBLIC},
    utils::PublicKey,
    Result,
};
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
/// Wrapper for the parameters needed by MakeCredential
pub struct MakeCredParams {
    /// TPM name of the object
    name: Vec<u8>,
    /// Encoding of the public parameters of the object whose name
    /// will be included in the credential computations
    public: Vec<u8>,
    /// Public part of the key used to protect the credential
    attesting_key_pub: PublicKey,
}

impl MakeCredParams {
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    pub fn attesting_key_pub(&self) -> &PublicKey {
        &self.attesting_key_pub
    }
}

impl TransientKeyContext {
    /// Get the data required to perform a MakeCredential
    ///
    /// # Parameters
    ///
    /// * `object` - the object whose TPM name will be included in
    /// the credential
    /// * `key` - the key to be used to encrypt the secret that wraps
    /// the credential
    ///
    /// **Note**: If no `key` is given, the default Endorsement Key
    /// will be used.  
    pub fn get_make_cred_params(
        &mut self,
        object: ObjectWrapper,
        key: Option<ObjectWrapper>,
    ) -> Result<MakeCredParams> {
        let object_handle = self.load_key(object.params, object.material, None)?;
        let (object_public, object_name, _) =
            self.context.read_public(object_handle).or_else(|e| {
                self.context.flush_context(object_handle.into())?;
                Err(e)
            })?;
        self.context.flush_context(object_handle.into())?;

        let public = TPM2B_PUBLIC::from(object_public);
        let public = unsafe {
            std::mem::transmute::<TPMT_PUBLIC, [u8; std::mem::size_of::<TPMT_PUBLIC>()]>(
                public.publicArea,
            )
        };
        let attesting_key_pub = match key {
            None => {
                let key_handle =
                    ek::create_ek_object(&mut self.context, AsymmetricAlgorithm::Rsa, None)?;
                let (attesting_key_pub, _, _) =
                    self.context.read_public(key_handle).or_else(|e| {
                        self.context.flush_context(key_handle.into())?;
                        Err(e)
                    })?;
                self.context.flush_context(key_handle.into())?;

                attesting_key_pub.try_into()?
            }
            Some(key) => key.material.public,
        };
        Ok(MakeCredParams {
            name: object_name.value().to_vec(),
            public: public.to_vec(),
            attesting_key_pub,
        })
    }

    /// Perform an ActivateCredential operation for the given object
    ///
    /// # Parameters
    ///
    /// * `object` - the object whose TPM name is included in the credential
    /// * `key` - the key used to encrypt the secret that wraps the credential
    /// * `credential_blob` - encrypted credential that will be returned by the
    /// TPM
    /// * `secret` - encrypted secret that was used to encrypt the credential
    ///
    /// **Note**: if no `key` is given, the default Endorsement Key
    /// will be used. You can find more information about the default Endorsement
    /// Key in the [ek] module.
    pub fn activate_credential(
        &mut self,
        object: ObjectWrapper,
        key: Option<ObjectWrapper>,
        credential_blob: Vec<u8>,
        secret: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let credential_blob = IDObject::try_from(credential_blob)?;
        let secret = EncryptedSecret::try_from(secret)?;
        let object_handle = self.load_key(object.params, object.material, object.auth)?;
        let session_2;
        let key_handle = match key {
            None => {
                // No key was given, use the EK. This requires using a Policy session
                session_2 = self
                    .context
                    .start_auth_session(
                        None,
                        None,
                        None,
                        SessionType::Policy,
                        SymmetricDefinition::AES_128_CFB,
                        HashingAlgorithm::Sha256,
                    )
                    .or_else(|e| {
                        self.context.flush_context(object_handle.into())?;
                        Err(e)
                    })?;
                let _ = self.context.policy_secret(
                    PolicySession::try_from(session_2.unwrap())
                        .expect("Failed to convert auth session to policy session"),
                    AuthHandle::Endorsement,
                    Default::default(),
                    Default::default(),
                    Default::default(),
                    None,
                );
                ek::create_ek_object(&mut self.context, AsymmetricAlgorithm::Rsa, None).or_else(
                    |e| {
                        self.context.flush_context(object_handle.into())?;
                        self.context
                            .flush_context(SessionHandle::from(session_2).into())?;
                        Err(e)
                    },
                )?
            }
            Some(key) => {
                // Load key and create a HMAC session for it
                session_2 = self
                    .context
                    .start_auth_session(
                        None,
                        None,
                        None,
                        SessionType::Hmac,
                        SymmetricDefinition::AES_128_CFB,
                        HashingAlgorithm::Sha256,
                    )
                    .or_else(|e| {
                        self.context.flush_context(object_handle.into())?;
                        Err(e)
                    })?;
                self.load_key(key.params, key.material, key.auth)
                    .or_else(|e| {
                        self.context.flush_context(object_handle.into())?;
                        self.context
                            .flush_context(SessionHandle::from(session_2).into())?;
                        Err(e)
                    })?
            }
        };

        let (session_1, _, _) = self.context.sessions();
        let credential = self
            .context
            .execute_with_sessions((session_1, session_2, None), |ctx| {
                ctx.activate_credential(object_handle, key_handle, credential_blob, secret)
            })
            .or_else(|e| {
                self.context.flush_context(object_handle.into())?;
                self.context.flush_context(key_handle.into())?;
                self.context
                    .flush_context(SessionHandle::from(session_2).into())?;
                Err(e)
            })?;

        self.context.flush_context(object_handle.into())?;
        self.context.flush_context(key_handle.into())?;
        self.context
            .flush_context(SessionHandle::from(session_2).into())?;
        Ok(credential.value().to_vec())
    }
}
