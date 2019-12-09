// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::constants::*;
use crate::response_code::{Result, Tss2ResponseCode};
use crate::tss2_esys::*;
use crate::utils::{self, get_rsa_public, PublicIdUnion, TpmsContext};
use crate::{Context, Tcti, NO_NON_AUTH_SESSIONS, NO_SESSIONS};
use std::convert::{TryFrom, TryInto};

pub type AuthValue = Vec<u8>;

pub struct TransientObjectContext {
    pub context: Context,
    root_key_handle: ESYS_TR,
}

impl TransientObjectContext {
    pub fn new(
        tcti: Tcti,
        root_key_size: usize,
        root_key_auth_size: usize,
        owner_hierarchy_auth: &[u8],
    ) -> Result<Self> {
        if root_key_auth_size > 32 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        if root_key_size < 1024 {
            return Err(Tss2ResponseCode::new(TPM2_RC_KEY_SIZE));
        }
        let mut context = Context::new(tcti)?;
        let root_key_auth: Vec<u8> = if root_key_auth_size > 0 {
            context.get_random(NO_SESSIONS, root_key_auth_size)?
        } else {
            vec![]
        };
        if !owner_hierarchy_auth.is_empty() {
            context.set_handle_auth(ESYS_TR_RH_OWNER, owner_hierarchy_auth)?;
        }

        let root_key_handle = context.create_primary_key(
            NO_SESSIONS,
            ESYS_TR_RH_OWNER,
            &get_rsa_public(true, true, false, root_key_size.try_into().unwrap()),
            &root_key_auth,
            &[],
            &[],
            &[],
        )?;

        let new_session = context.start_auth_session(
            NO_NON_AUTH_SESSIONS,
            root_key_handle,
            ESYS_TR_NONE,
            &[],
            TPM2_SE_HMAC,
            utils::TpmtSymDefBuilder::aes_256_cfb(),
            TPM2_ALG_SHA256,
        )?;
        let session_attr = utils::TpmaSession::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT);
        context.set_session_attr(new_session, session_attr)?;
        context.set_session(new_session);
        Ok(TransientObjectContext {
            context,
            root_key_handle,
        })
    }

    pub fn create_rsa_signing_key(
        &mut self,
        key_size: usize,
        auth_size: usize,
    ) -> Result<(TpmsContext, AuthValue)> {
        if auth_size > 32 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        if key_size < 1024 {
            return Err(Tss2ResponseCode::new(TPM2_RC_KEY_SIZE));
        }
        let key_auth = if auth_size > 0 {
            self.context.get_random(NO_SESSIONS, auth_size)?
        } else {
            vec![]
        };
        let (key_priv, key_pub) = self.context.create_key(
            NO_SESSIONS,
            self.root_key_handle,
            &get_rsa_public(false, false, true, key_size.try_into().unwrap()),
            &key_auth,
            &[],
            &[],
            &[],
        )?;
        let key_handle = self
            .context
            .load(NO_SESSIONS, self.root_key_handle, key_priv, key_pub)?;

        let key_context = self.context.context_save(key_handle)?;
        self.context.flush_context(key_handle)?;
        Ok((key_context, key_auth))
    }

    pub fn load_external_rsa_public_key(&mut self, public_key: &[u8]) -> Result<TpmsContext> {
        if public_key.len() > 512 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        let mut pk_buffer = [0u8; 512];
        pk_buffer[..public_key.len()].clone_from_slice(&public_key[..public_key.len()]);

        let pk = TPMU_PUBLIC_ID {
            rsa: TPM2B_PUBLIC_KEY_RSA {
                size: public_key.len().try_into().unwrap(),
                buffer: pk_buffer,
            },
        };

        let mut public = get_rsa_public(
            false,
            false,
            true,
            u16::try_from(public_key.len()).unwrap() * 8u16,
        );
        public.publicArea.unique = pk;

        let key_handle = self
            .context
            .load_external_public(NO_SESSIONS, &public, TPM2_RH_OWNER)?;

        let key_context = self.context.context_save(key_handle)?;
        self.context.flush_context(key_handle)?;

        Ok(key_context)
    }

    pub fn read_public_key(
        &mut self,
        key_context: TpmsContext,
        key_auth: &[u8],
    ) -> Result<Vec<u8>> {
        let key_handle = self.context.context_load(key_context)?;
        self.context.set_handle_auth(key_handle, key_auth)?;

        let key_pub_id = self.context.read_public(NO_SESSIONS, key_handle)?;
        let key = match PublicIdUnion::from_public(&key_pub_id) {
            PublicIdUnion::Rsa(pub_key) => {
                let mut key = pub_key.buffer.to_vec();
                key.truncate(pub_key.size.try_into().unwrap());
                key
            }
            _ => unimplemented!(),
        };

        Ok(key)
    }

    pub fn sign(
        &mut self,
        key_context: TpmsContext,
        key_auth: &[u8],
        digest: &[u8],
    ) -> Result<utils::Signature> {
        let key_handle = self.context.context_load(key_context)?;
        self.context.set_handle_auth(key_handle, key_auth)?;

        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = self
            .context
            .sign(NO_SESSIONS, key_handle, digest, scheme, &validation)?;
        self.context.flush_context(key_handle)?;
        Ok(signature)
    }

    pub fn verify_signature(
        &mut self,
        key_context: TpmsContext,
        digest: &[u8],
        signature: utils::Signature,
    ) -> Result<TPMT_TK_VERIFIED> {
        let key_handle = self.context.context_load(key_context)?;

        let verified = self.context.verify_signature(
            NO_SESSIONS,
            key_handle,
            digest,
            &signature.try_into()?,
        )?;
        self.context.flush_context(key_handle)?;
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Tcti;

    const HASH: [u8; 32] = [
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0x37, 0x78,
    ];

    #[test]
    fn transient_test() {
        let mut ctx = TransientObjectContext::new(Tcti::Mssim, 2048, 32, &[]).unwrap();
        let (key, auth) = ctx.create_rsa_signing_key(2048, 16).unwrap();
        let signature = ctx.sign(key.clone(), &auth, &HASH).unwrap();
        let pub_key = ctx.read_public_key(key.clone(), &auth).unwrap();
        let pub_key = ctx.load_external_rsa_public_key(&pub_key).unwrap();
        ctx.verify_signature(pub_key, &HASH, signature).unwrap();
    }
}
