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
#![allow(dead_code)]

#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
#[allow(clippy::all)]
// There is an issue where long double become u128 in extern blocks. Check this issue:
// https://github.com/rust-lang/rust-bindgen/issues/1549
#[allow(improper_ctypes)]
pub mod tss2_esys {
    include!(concat!(env!("OUT_DIR"), "/tss2_esys_bindings.rs"));
}
pub mod abstraction;
#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code
)]
#[allow(clippy::all)]
pub mod constants;
pub mod response_code;
pub mod utils;

use log::{error, info};
use mbox::MBox;
use response_code::Result;
use response_code::Tss2ResponseCode;
use std::collections::HashSet;
use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::ptr::{null, null_mut};
use tss2_esys::*;
use utils::{Signature, TpmaSession, TpmsContext};

#[macro_use]
macro_rules! wrap_buffer {
    ($buf:expr, $buf_type:ty, $buf_size:expr) => {{
        let mut buffer = [0u8; $buf_size];
        buffer[..$buf.len()].clone_from_slice(&$buf[..$buf.len()]);
        let mut buf_struct: $buf_type = Default::default();
        buf_struct.size = $buf.len().try_into().unwrap();
        buf_struct.buffer = buffer;
        buf_struct
    }};
}

pub type Sessions = (ESYS_TR, ESYS_TR);
pub const NO_SESSIONS: Sessions = (ESYS_TR_NONE, ESYS_TR_NONE);
pub const NO_NON_AUTH_SESSIONS: (ESYS_TR, ESYS_TR, ESYS_TR) =
    (ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);

// Possible TCTI to use with the ESYS API.
// TODO: add to each variant a structure for its configuration. Currently using the default
// configuration.
pub enum Tcti {
    Device,
    Mssim,
    Tabrmd,
}

const DEVICE: &str = "device";
const MSSIM: &str = "mssim";
const TABRMD: &str = "tabrmd";
use constants::*;

/// Safe abstraction over an ESYS_CONTEXT.
pub struct Context {
    // TODO: explain Option
    esys_context: Option<MBox<ESYS_CONTEXT>>,
    session: ESYS_TR,
    tcti_context: Option<MBox<TSS2_TCTI_CONTEXT>>,
    open_handles: HashSet<ESYS_TR>,
}

impl Context {
    pub fn new(tcti: Tcti) -> Result<Self> {
        let mut esys_context = null_mut();
        let mut tcti_context = null_mut();

        let tcti_name_conf = match tcti {
            Tcti::Device => DEVICE,
            Tcti::Mssim => MSSIM,
            Tcti::Tabrmd => TABRMD,
        };
        let tcti_name_conf = CString::new(tcti_name_conf).or_else(|e| {
            error!("Error when allocating a CString: {}.", e);
            // Invalid response code but signaling an error.
            Err(Tss2ResponseCode::new(1))
        })?;

        let ret = unsafe {
            tss2_esys::Tss2_TctiLdr_Initialize(tcti_name_conf.as_ptr(), &mut tcti_context)
        };
        let ret = Tss2ResponseCode::new(ret);
        if !ret.is_success() {
            error!("Error when creating a TCTI context: {}.", ret);
            return Err(ret);
        }
        let mut tcti_context = unsafe { Some(MBox::from_raw(tcti_context)) };

        let ret = unsafe {
            tss2_esys::Esys_Initialize(
                &mut esys_context,
                tcti_context.as_mut().unwrap().as_mut_ptr(),
                null_mut(),
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            let esys_context = unsafe { Some(MBox::from_raw(esys_context)) };
            let mut context = Context {
                esys_context,
                session: ESYS_TR_NONE,
                tcti_context,
                open_handles: HashSet::new(),
            };
            let session = context.start_auth_session(
                NO_NON_AUTH_SESSIONS,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )?;
            let session_attr = TpmaSession::new()
                .with_flag(TPMA_SESSION_DECRYPT)
                .with_flag(TPMA_SESSION_ENCRYPT);
            context.set_session_attr(session, session_attr)?;
            context.session = session;
            Ok(context)
        } else {
            error!("Error when creating a new context: {}.", ret);
            Err(ret)
        }
    }

    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn start_auth_session(
        &mut self,
        non_auth_sessions: (ESYS_TR, ESYS_TR, ESYS_TR),
        tpm_key: ESYS_TR,
        bind: ESYS_TR,
        nonce: &[u8],
        session_type: TPM2_SE,
        symmetric: TPMT_SYM_DEF,
        auth_hash: TPMI_ALG_HASH,
    ) -> Result<ESYS_TR> {
        if nonce.len() > 64 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }

        let nonce_caller = wrap_buffer!(nonce, TPM2B_NONCE, 64);
        let mut sess = ESYS_TR_NONE;

        let ret = unsafe {
            tss2_esys::Esys_StartAuthSession(
                self.mut_context(),
                tpm_key,
                bind,
                non_auth_sessions.0,
                non_auth_sessions.1,
                non_auth_sessions.2,
                if nonce.is_empty() {
                    null()
                } else {
                    &nonce_caller
                },
                session_type,
                &symmetric,
                auth_hash,
                &mut sess,
            )
        };

        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            self.open_handles.insert(sess);
            Ok(sess)
        } else {
            error!("Error when creating a session: {}.", ret);
            Err(ret)
        }
    }

    pub fn set_session(&mut self, session_handle: ESYS_TR) {
        self.session = session_handle;
    }

    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create_primary_key(
        &mut self,
        sessions: Sessions,
        primary_handle: ESYS_TR,
        public: &TPM2B_PUBLIC,
        auth_value: &[u8],
        initial_data: &[u8],
        outside_info: &[u8],
        creation_pcrs: &[TPMS_PCR_SELECTION],
    ) -> Result<ESYS_TR> {
        if auth_value.len() > 64
            || initial_data.len() > 256
            || outside_info.len() > 64
            || creation_pcrs.len() > 16
        {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }

        let sensitive_create = TPM2B_SENSITIVE_CREATE {
            size: std::mem::size_of::<TPMS_SENSITIVE_CREATE>()
                .try_into()
                .unwrap(),
            sensitive: TPMS_SENSITIVE_CREATE {
                userAuth: wrap_buffer!(auth_value, TPM2B_AUTH, 64),
                data: wrap_buffer!(initial_data, TPM2B_SENSITIVE_DATA, 256),
            },
        };

        let outside_info = wrap_buffer!(outside_info, TPM2B_DATA, 64);
        let mut creation_pcrs_buffer = [Default::default(); 16];
        creation_pcrs_buffer[..creation_pcrs.len()]
            .clone_from_slice(&creation_pcrs[..creation_pcrs.len()]);
        let creation_pcrs = TPML_PCR_SELECTION {
            count: creation_pcrs.len().try_into().unwrap(),
            pcrSelections: creation_pcrs_buffer,
        };

        let mut outpublic = null_mut();
        let mut creation_data = null_mut();
        let mut creation_hash = null_mut();
        let mut creation_ticket = null_mut();
        let mut prim_key_handle = ESYS_TR_NONE;

        let ret = unsafe {
            Esys_CreatePrimary(
                self.mut_context(),
                primary_handle,
                self.session,
                sessions.0,
                sessions.1,
                &sensitive_create,
                public,
                &outside_info,
                &creation_pcrs,
                &mut prim_key_handle,
                &mut outpublic,
                &mut creation_data,
                &mut creation_hash,
                &mut creation_ticket,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            unsafe {
                MBox::from_raw(outpublic);
                MBox::from_raw(creation_data);
                MBox::from_raw(creation_hash);
                MBox::from_raw(creation_ticket);
            }
            self.open_handles.insert(prim_key_handle);
            Ok(prim_key_handle)
        } else {
            error!("Error in creating primary key: {}.", ret);
            Err(ret)
        }
    }

    // TODO: Fix when compacting the arguments into a struct
    #[allow(clippy::too_many_arguments)]
    pub fn create_key(
        &mut self,
        sessions: Sessions,
        parent_handle: ESYS_TR,
        public: &TPM2B_PUBLIC,
        auth_value: &[u8],
        initial_data: &[u8],
        outside_info: &[u8],
        creation_pcrs: &[TPMS_PCR_SELECTION],
    ) -> Result<(TPM2B_PRIVATE, TPM2B_PUBLIC)> {
        if auth_value.len() > 64
            || initial_data.len() > 256
            || outside_info.len() > 64
            || creation_pcrs.len() > 16
        {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }

        let sensitive_create = TPM2B_SENSITIVE_CREATE {
            size: std::mem::size_of::<TPMS_SENSITIVE_CREATE>()
                .try_into()
                .unwrap(),
            sensitive: TPMS_SENSITIVE_CREATE {
                userAuth: wrap_buffer!(auth_value, TPM2B_AUTH, 64),
                data: wrap_buffer!(initial_data, TPM2B_SENSITIVE_DATA, 256),
            },
        };

        let outside_info = wrap_buffer!(outside_info, TPM2B_DATA, 64);

        let mut creation_pcrs_buffer = [Default::default(); 16];
        creation_pcrs_buffer[..creation_pcrs.len()]
            .clone_from_slice(&creation_pcrs[..creation_pcrs.len()]);
        let creation_pcrs = TPML_PCR_SELECTION {
            count: creation_pcrs.len().try_into().unwrap(),
            pcrSelections: creation_pcrs_buffer,
        };

        let mut outpublic = null_mut();
        let mut outprivate = null_mut();
        let mut creation_data = null_mut();
        let mut digest = null_mut();
        let mut creation = null_mut();

        let ret = unsafe {
            Esys_Create(
                self.mut_context(),
                parent_handle,
                self.session,
                sessions.0,
                sessions.1,
                &sensitive_create,
                public,
                &outside_info,
                &creation_pcrs,
                &mut outprivate,
                &mut outpublic,
                &mut creation_data,
                &mut digest,
                &mut creation,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            let outprivate = unsafe { MBox::from_raw(outprivate) };
            let outpublic = unsafe { MBox::from_raw(outpublic) };
            unsafe {
                MBox::from_raw(creation_data);
                MBox::from_raw(digest);
                MBox::from_raw(creation);
            }
            Ok((*outprivate, *outpublic))
        } else {
            error!("Error in creating derived key: {}.", ret);
            Err(ret)
        }
    }

    pub fn load(
        &mut self,
        sessions: Sessions,
        parent_handle: ESYS_TR,
        private: TPM2B_PRIVATE,
        public: TPM2B_PUBLIC,
    ) -> Result<ESYS_TR> {
        let mut handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_Load(
                self.mut_context(),
                parent_handle,
                self.session,
                sessions.0,
                sessions.1,
                &private,
                &public,
                &mut handle,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            self.open_handles.insert(handle);
            Ok(handle)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn sign(
        &mut self,
        sessions: Sessions,
        key_handle: ESYS_TR,
        digest: &[u8],
        scheme: TPMT_SIG_SCHEME,
        validation: &TPMT_TK_HASHCHECK,
    ) -> Result<Signature> {
        if digest.len() > 64 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        let mut signature = null_mut();
        let digest = wrap_buffer!(digest, TPM2B_DIGEST, 64);
        let ret = unsafe {
            Esys_Sign(
                self.mut_context(),
                key_handle,
                self.session,
                sessions.0,
                sessions.1,
                &digest,
                &scheme,
                validation,
                &mut signature,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            let signature = unsafe { MBox::from_raw(signature) };
            Ok((*signature).try_into()?)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn verify_signature(
        &mut self,
        sessions: Sessions,
        key_handle: ESYS_TR,
        digest: &[u8],
        signature: &TPMT_SIGNATURE,
    ) -> Result<TPMT_TK_VERIFIED> {
        if digest.len() > 64 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        let mut validation = null_mut();
        let digest = wrap_buffer!(digest, TPM2B_DIGEST, 64);
        let ret = unsafe {
            Esys_VerifySignature(
                self.mut_context(),
                key_handle,
                self.session,
                sessions.0,
                sessions.1,
                &digest,
                signature,
                &mut validation,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            let validation = unsafe { MBox::from_raw(validation) };
            Ok(*validation)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn load_external(
        &mut self,
        sessions: Sessions,
        private: &TPM2B_SENSITIVE,
        public: &TPM2B_PUBLIC,
        hierarchy: TPMI_RH_HIERARCHY,
    ) -> Result<ESYS_TR> {
        let mut key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_LoadExternal(
                self.mut_context(),
                self.session,
                sessions.0,
                sessions.1,
                private,
                public,
                hierarchy,
                &mut key_handle,
            )
        };

        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            self.open_handles.insert(key_handle);
            Ok(key_handle)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn load_external_public(
        &mut self,
        sessions: Sessions,
        public: &TPM2B_PUBLIC,
        hierarchy: TPMI_RH_HIERARCHY,
    ) -> Result<ESYS_TR> {
        let mut key_handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_LoadExternal(
                self.mut_context(),
                self.session,
                sessions.0,
                sessions.1,
                null(),
                public,
                hierarchy,
                &mut key_handle,
            )
        };

        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            self.open_handles.insert(key_handle);
            Ok(key_handle)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn read_public(&mut self, sessions: Sessions, key_handle: ESYS_TR) -> Result<TPM2B_PUBLIC> {
        let mut public = null_mut();
        let mut name = null_mut();
        let mut qualified_name = null_mut();
        let ret = unsafe {
            Esys_ReadPublic(
                self.mut_context(),
                key_handle,
                self.session,
                sessions.0,
                sessions.1,
                &mut public,
                &mut name,
                &mut qualified_name,
            )
        };
        let ret = Tss2ResponseCode::new(ret);

        if ret.is_success() {
            unsafe {
                MBox::from_raw(name);
                MBox::from_raw(qualified_name);
            }
            let public = unsafe { MBox::<TPM2B_PUBLIC>::from_raw(public) };
            Ok(*public)
        } else {
            error!("Error in loading: {}.", ret);
            Err(ret)
        }
    }

    pub fn flush_context(&mut self, handle: ESYS_TR) -> Result<()> {
        let ret = unsafe { Esys_FlushContext(self.mut_context(), handle) };
        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            self.open_handles.remove(&handle);
            Ok(())
        } else {
            error!("Error in flushing context: {}.", ret);
            Err(ret)
        }
    }

    pub fn context_save(&mut self, handle: ESYS_TR) -> Result<TpmsContext> {
        let mut context = null_mut();
        let ret = unsafe { Esys_ContextSave(self.mut_context(), handle, &mut context) };

        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            let context = unsafe { MBox::<TPMS_CONTEXT>::from_raw(context) };
            Ok((*context).into())
        } else {
            error!("Error in saving context: {}.", ret);
            Err(ret)
        }
    }

    pub fn context_load(&mut self, context: TpmsContext) -> Result<ESYS_TR> {
        let mut handle = ESYS_TR_NONE;
        let ret = unsafe {
            Esys_ContextLoad(
                self.mut_context(),
                &TPMS_CONTEXT::try_from(context)?,
                &mut handle,
            )
        };

        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            self.open_handles.insert(handle);
            Ok(handle)
        } else {
            error!("Error in loading context: {}.", ret);
            Err(ret)
        }
    }

    pub fn get_random(&mut self, sessions: Sessions, num_bytes: usize) -> Result<Vec<u8>> {
        let mut buffer = null_mut();
        let ret = unsafe {
            Esys_GetRandom(
                self.mut_context(),
                self.session,
                sessions.0,
                sessions.1,
                num_bytes.try_into().unwrap(),
                &mut buffer,
            )
        };

        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            let buffer = unsafe { MBox::from_raw(buffer) };
            let mut random = buffer.buffer.to_vec();
            random.truncate(buffer.size.try_into().unwrap());
            Ok(random)
        } else {
            error!("Error in flushing context: {}.", ret);
            Err(ret)
        }
    }

    pub fn set_handle_auth(&mut self, handle: ESYS_TR, auth_value: &[u8]) -> Result<()> {
        if auth_value.len() > 64 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }

        let auth = wrap_buffer!(auth_value, TPM2B_AUTH, 64);
        let ret = unsafe { Esys_TR_SetAuth(self.mut_context(), handle, &auth) };
        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            Ok(())
        } else {
            Err(ret)
        }
    }

    pub fn set_session_attr(&mut self, handle: ESYS_TR, attrs: TpmaSession) -> Result<()> {
        let ret = unsafe {
            Esys_TRSess_SetAttributes(self.mut_context(), handle, attrs.flags(), attrs.mask())
        };
        let ret = Tss2ResponseCode::new(ret);
        if ret.is_success() {
            Ok(())
        } else {
            Err(ret)
        }
    }

    fn mut_context(&mut self) -> *mut ESYS_CONTEXT {
        self.esys_context.as_mut().unwrap().as_mut_ptr()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        info!("Closing context.");

        // Flush the open handles.
        self.open_handles.clone().iter().for_each(|handle| {
            info!("Flushing handle {}", *handle);
            if let Err(e) = self.flush_context(*handle) {
                error!("Error when dropping the context: {}.", e);
            }
        });

        let esys_context = self.esys_context.take().unwrap();
        let tcti_context = self.tcti_context.take().unwrap();

        // Close the TCTI context.
        unsafe {
            tss2_esys::Tss2_TctiLdr_Finalize(
                &mut tcti_context.into_raw() as *mut *mut TSS2_TCTI_CONTEXT
            )
        };

        // Close the context.
        unsafe { tss2_esys::Esys_Finalize(&mut esys_context.into_raw() as *mut *mut ESYS_CONTEXT) };
        info!("Context closed.");
    }
}

#[cfg(test)]
mod tests {
    const HASH: [u8; 64] = [
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0x69, 0x3E, 0xDB, 0x1B, 0x22, 0x79, 0x03, 0xF4, 0xC0, 0xBF, 0xD6, 0x91, 0x76, 0x37, 0x84,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0xA2, 0x94, 0x8E, 0x92, 0x50, 0x35, 0xC2, 0x8C, 0x5C, 0x3C, 0xCA, 0xFE, 0x18, 0xE8, 0x81,
        0x37, 0x78, 0x37, 0x78,
    ];

    const KEY: [u8; 512] = [
        231, 97, 201, 180, 0, 1, 185, 150, 85, 90, 174, 188, 105, 133, 188, 3, 206, 5, 222, 71,
        185, 1, 209, 243, 36, 130, 250, 116, 17, 0, 24, 4, 25, 225, 250, 198, 245, 210, 140, 23,
        139, 169, 15, 193, 4, 145, 52, 138, 149, 155, 238, 36, 74, 152, 179, 108, 200, 248, 250,
        100, 115, 214, 166, 165, 1, 27, 51, 11, 11, 244, 218, 157, 3, 174, 171, 142, 45, 8, 9, 36,
        202, 171, 165, 43, 208, 186, 232, 15, 241, 95, 81, 174, 189, 30, 213, 47, 86, 115, 239, 49,
        214, 235, 151, 9, 189, 174, 144, 238, 200, 201, 241, 157, 43, 37, 6, 96, 94, 152, 159, 205,
        54, 9, 181, 14, 35, 246, 49, 150, 163, 118, 242, 59, 54, 42, 221, 215, 248, 23, 18, 223,
        179, 229, 0, 204, 65, 69, 166, 180, 11, 49, 131, 96, 163, 96, 158, 7, 109, 119, 208, 17,
        237, 125, 187, 121, 94, 65, 2, 86, 105, 68, 51, 197, 73, 108, 185, 231, 126, 199, 81, 1,
        251, 211, 45, 47, 15, 113, 135, 197, 152, 239, 180, 111, 18, 192, 136, 222, 11, 99, 41,
        248, 205, 253, 209, 56, 214, 32, 225, 3, 49, 161, 58, 57, 190, 69, 86, 95, 185, 184, 155,
        76, 8, 122, 104, 81, 222, 234, 246, 40, 98, 182, 90, 160, 111, 74, 102, 36, 148, 99, 69,
        207, 214, 104, 87, 128, 238, 26, 121, 107, 166, 4, 64, 5, 210, 164, 162, 189, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    use crate::utils;
    use crate::*;

    #[test]
    fn simple_test() {
        env_logger::init();

        let mut context = Context::new(Tcti::Mssim).unwrap();
        let key_auth: Vec<u8> = context.get_random(NO_SESSIONS, 16).unwrap();

        let prim_key_handle = context
            .create_primary_key(
                NO_SESSIONS,
                ESYS_TR_RH_OWNER,
                &utils::get_rsa_public(true, true, false, 2048),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();

        dbg!(prim_key_handle);

        let new_session = context
            .start_auth_session(
                NO_NON_AUTH_SESSIONS,
                ESYS_TR_NONE,
                prim_key_handle,
                &[],
                TPM2_SE_HMAC,
                utils::TpmtSymDefBuilder::aes_256_cfb(),
                TPM2_ALG_SHA256,
            )
            .unwrap();
        let session_attr = TpmaSession::new()
            .with_flag(TPMA_SESSION_DECRYPT)
            .with_flag(TPMA_SESSION_ENCRYPT);
        context.set_session_attr(new_session, session_attr).unwrap();
        context.set_session(new_session);

        let (key_priv, key_pub) = context
            .create_key(
                NO_SESSIONS,
                prim_key_handle,
                &utils::get_rsa_public(false, false, true, 1024),
                &key_auth,
                &[],
                &[],
                &[],
            )
            .unwrap();
        let key_handle = context
            .load(NO_SESSIONS, prim_key_handle, key_priv, key_pub)
            .unwrap();
        dbg!(key_handle);

        let key_context = context.context_save(key_handle).unwrap();
        let key_handle = context.context_load(key_context).unwrap();
        context.set_handle_auth(key_handle, &key_auth).unwrap();
        dbg!(key_handle);
        let scheme = TPMT_SIG_SCHEME {
            scheme: TPM2_ALG_NULL,
            details: Default::default(),
        };
        let validation = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        };
        let signature = context
            .sign(NO_SESSIONS, key_handle, &HASH[..32], scheme, &validation)
            .unwrap();
        print!("Signature: ");
        for x in &signature.signature {
            print!("{}, ", x);
        }
        println!();
        dbg!(
            context
                .verify_signature(
                    NO_SESSIONS,
                    key_handle,
                    &HASH[..32],
                    &signature.try_into().unwrap()
                )
                .unwrap()
                .tag
        );
    }
}
