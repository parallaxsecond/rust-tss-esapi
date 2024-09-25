// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{KeyHandle, ObjectHandle},
    structures::{
        Attest, AttestBuffer, CreationTicket, Data, Digest, PcrSelectionList, Signature,
        SignatureScheme,
    },
    tss2_esys::{Esys_Certify, Esys_Quote},
    Context, Result, ReturnCode,
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;
use tss_esapi_sys::Esys_CertifyCreation;

impl Context {
    /// Prove that an object is loaded in the TPM
    ///
    /// # Arguments
    /// * `object_handle` - Handle of the object to be certified
    /// * `signing_key_handle` - Handle of the key used to sign the attestation buffer
    /// * `qualifying_data` - Qualifying data
    /// * `signing_scheme` - Signing scheme to use if the scheme for `signing_key_handle` is `Null`.
    ///
    /// The object may be any object that is loaded with [Self::load()] or [Self::create_primary()]. An object that
    /// only has its public area loaded may not be certified.
    ///
    /// The `signing_key_handle` must be usable for signing.
    ///
    /// If `signing_key_handle` has the Restricted attribute set to `true` then `signing_scheme` must be
    /// [SignatureScheme::Null].
    ///
    /// # Returns
    /// The command returns a tuple consisting of:
    /// * `attest_data` - TPM-generated attestation data.
    /// * `signature` - Signature for the attestation data.
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use std::convert::TryFrom;
    /// # use tss_esapi::{
    /// #     abstraction::cipher::Cipher,
    /// #     handles::KeyHandle,
    /// #     interface_types::{
    /// #         algorithm::{HashingAlgorithm, RsaSchemeAlgorithm, SignatureSchemeAlgorithm},
    /// #         key_bits::RsaKeyBits,
    /// #         reserved_handles::Hierarchy,
    /// #     },
    /// #     structures::{
    /// #         RsaExponent, RsaScheme, SymmetricDefinition,
    /// #     },
    /// #     utils::{create_unrestricted_signing_rsa_public, create_restricted_decryption_rsa_public},
    /// # };
    /// use std::convert::TryInto;
    /// use tss_esapi::{
    ///     structures::{Data, SignatureScheme},
    ///     interface_types::session_handles::AuthSession,
    /// };
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let qualifying_data = vec![0xff; 16];
    /// # let signing_key_pub = create_unrestricted_signing_rsa_public(
    /// #         RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    /// #         .expect("Failed to create RSA scheme"),
    /// #     RsaKeyBits::Rsa2048,
    /// #     RsaExponent::default(),
    /// # )
    /// # .expect("Failed to create an unrestricted signing rsa public structure");
    /// # let sign_key_handle = context
    /// #     .execute_with_nullauth_session(|ctx| {
    /// #         ctx.create_primary(Hierarchy::Owner, signing_key_pub, None, None, None, None)
    /// #     })
    /// #     .unwrap()
    /// #     .key_handle;
    /// # let decryption_key_pub = create_restricted_decryption_rsa_public(
    /// #         Cipher::aes_256_cfb()
    /// #         .try_into()
    /// #         .expect("Failed to create symmetric object"),
    /// #     RsaKeyBits::Rsa2048,
    /// #     RsaExponent::default(),
    /// # )
    /// # .expect("Failed to create a restricted decryption rsa public structure");
    /// # let obj_key_handle = context
    /// #     .execute_with_nullauth_session(|ctx| {
    /// #         ctx.create_primary(
    /// #             Hierarchy::Owner,
    /// #             decryption_key_pub,
    /// #             None,
    /// #             None,
    /// #             None,
    /// #             None,
    /// #         )
    /// #     })
    /// #     .unwrap()
    /// #     .key_handle;
    /// let (attest, signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             Some(AuthSession::Password),
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.certify(
    ///                 obj_key_handle.into(),
    ///                 sign_key_handle,
    ///                 Data::try_from(qualifying_data).unwrap(),
    ///                 SignatureScheme::Null,
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to certify object handle");
    /// ```
    pub fn certify(
        &mut self,
        object_handle: ObjectHandle,
        signing_key_handle: KeyHandle,
        qualifying_data: Data,
        signing_scheme: SignatureScheme,
    ) -> Result<(Attest, Signature)> {
        let mut certify_info_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_Certify(
                    self.mut_context(),
                    object_handle.into(),
                    signing_key_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &signing_scheme.into(),
                    &mut certify_info_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error in certifying: {:#010X}", ret);
            },
        )?;

        let certify_info = Context::ffi_data_to_owned(certify_info_ptr);
        let signature = Context::ffi_data_to_owned(signature_ptr);
        Ok((
            Attest::try_from(AttestBuffer::try_from(certify_info)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Prove the association between an object and its creation data
    ///
    /// # Arguments
    /// * `signing_key_handle` - Handle of the key used to sign the attestation buffer
    /// * `object_handle` - Handle of the object to be certified
    /// * `qualifying_data` - Qualifying data
    /// * `creation_hash` - Digest of the creation data
    /// * `signing_scheme` - Signing scheme to use if the scheme for `signing_key_handle` is `Null`.
    /// * `creation_ticket` - CreationTicket returned at object creation time.
    ///
    /// The object may be any object that is loaded with [Self::load()] or [Self::create_primary()]. An object that
    /// only has its public area loaded may not be certified.
    ///
    /// The `signing_key_handle` must be usable for signing.
    ///
    /// If `signing_key_handle` has the Restricted attribute set to `true` then `signing_scheme` must be
    /// [SignatureScheme::Null].
    ///
    /// # Returns
    /// The command returns a tuple consisting of:
    /// * `attest_data` - TPM-generated attestation data.
    /// * `signature` - Signature for the attestation data.
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use std::convert::TryFrom;
    /// # use tss_esapi::{
    /// #     abstraction::cipher::Cipher,
    /// #     handles::KeyHandle,
    /// #     interface_types::{
    /// #         algorithm::{HashingAlgorithm, EccSchemeAlgorithm, SignatureSchemeAlgorithm},
    /// #         ecc::EccCurve,
    /// #         reserved_handles::Hierarchy,
    /// #     },
    /// #     structures::{
    /// #         EccScheme
    /// #     },
    /// #     utils::create_unrestricted_signing_ecc_public,
    /// # };
    /// use std::convert::TryInto;
    /// use tss_esapi::{
    ///     structures::{Data, SignatureScheme},
    ///     interface_types::session_handles::AuthSession,
    /// };
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let qualifying_data = vec![0xff; 16];
    /// # let signing_key_pub = create_unrestricted_signing_ecc_public(
    /// #         EccScheme::create(EccSchemeAlgorithm::EcDsa, Some(HashingAlgorithm::Sha256), None)
    /// #         .expect("Failed to create ECC scheme"),
    /// #         EccCurve::NistP256,
    /// # )
    /// # .expect("Failed to create an unrestricted signing ecc public structure");
    /// # let create_result = context
    /// #     .execute_with_nullauth_session(|ctx| {
    /// #         ctx.create_primary(Hierarchy::Owner, signing_key_pub, None, None, None, None)
    /// #     }).unwrap();
    /// let (attest, signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             None,
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.certify_creation(
    ///               create_result.key_handle,
    ///               create_result.key_handle.into(),
    ///               qualifying_data.try_into()?,
    ///               create_result.creation_hash,
    ///               SignatureScheme::Null,
    ///               create_result.creation_ticket,
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to certify creation");
    /// ```
    pub fn certify_creation(
        &mut self,
        signing_key_handle: KeyHandle,
        created_object: ObjectHandle,
        qualifying_data: Data,
        creation_hash: Digest,
        signing_scheme: SignatureScheme,
        creation_ticket: CreationTicket,
    ) -> Result<(Attest, Signature)> {
        let mut certify_info_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_CertifyCreation(
                    self.mut_context(),
                    signing_key_handle.into(),
                    created_object.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &creation_hash.into(),
                    &signing_scheme.into(),
                    &creation_ticket.try_into()?,
                    &mut certify_info_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error in certifying creation: {:#010X}", ret);
            },
        )?;

        let certify_info = Context::ffi_data_to_owned(certify_info_ptr);
        let signature = Context::ffi_data_to_owned(signature_ptr);
        Ok((
            Attest::try_from(AttestBuffer::try_from(certify_info)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Generate a quote on the selected PCRs
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
    pub fn quote(
        &mut self,
        signing_key_handle: KeyHandle,
        qualifying_data: Data,
        signing_scheme: SignatureScheme,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<(Attest, Signature)> {
        let mut quoted_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_Quote(
                    self.mut_context(),
                    signing_key_handle.into(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &signing_scheme.into(),
                    &pcr_selection_list.into(),
                    &mut quoted_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error in quoting PCR: {:#010X}", ret);
            },
        )?;

        let quoted = Context::ffi_data_to_owned(quoted_ptr);
        let signature = Context::ffi_data_to_owned(signature_ptr);
        Ok((
            Attest::try_from(AttestBuffer::try_from(quoted)?)?,
            Signature::try_from(signature)?,
        ))
    }

    // Missing function: GetSessionAuditDigest
    // Missing function: GestCommandAuditDigest
    // Missing function: GetTime
    // Missing function: CertifyX509
}
