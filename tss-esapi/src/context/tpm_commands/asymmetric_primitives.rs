// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::KeyHandle, structures::Data, structures::PublicKeyRSA, tss2_esys::*,
    utils::AsymSchemeUnion, Context, Error, Result,
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Perform an asymmetric RSA encryption.
    pub fn rsa_encrypt(
        &mut self,
        key_handle: KeyHandle,
        message: PublicKeyRSA,
        in_scheme: AsymSchemeUnion,
        label: Data,
    ) -> Result<PublicKeyRSA> {
        let mut out_data = null_mut();
        let ret = unsafe {
            Esys_RSA_Encrypt(
                self.mut_context(),
                key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &message.into(),
                &in_scheme.get_rsa_decrypt_struct(),
                &label.into(),
                &mut out_data,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let data = unsafe { PublicKeyRSA::try_from(*out_data)? };
            Ok(data)
        } else {
            error!("Error when performing RSA encryption: {}", ret);
            Err(ret)
        }
    }

    /// Perform an asymmetric RSA decryption.
    pub fn rsa_decrypt(
        &mut self,
        key_handle: KeyHandle,
        cipher_text: PublicKeyRSA,
        in_scheme: AsymSchemeUnion,
        label: Data,
    ) -> Result<PublicKeyRSA> {
        let mut message = null_mut();
        let ret = unsafe {
            Esys_RSA_Decrypt(
                self.mut_context(),
                key_handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &cipher_text.into(),
                &in_scheme.get_rsa_decrypt_struct(),
                &label.into(),
                &mut message,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let data = unsafe { PublicKeyRSA::try_from(*message)? };
            Ok(data)
        } else {
            error!("Error when performing RSA decryption: {}", ret);
            Err(ret)
        }
    }

    // Missing function: ECDH_KeyGen
    // Missing function: ECDH_ZGen
    // Missing function: ECC_Parameters
    // Missing function: ZGen_2Phase
}
