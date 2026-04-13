// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::{KeyHandle, ObjectHandle, SessionHandle},
    structures::{
        Attest, AttestBuffer, CreationTicket, Data, Digest, MaxBuffer, PcrSelectionList, Signature,
        SignatureScheme,
    },
    tss2_esys::{
        Esys_Certify, Esys_CertifyCreation, Esys_CertifyX509, Esys_GetCommandAuditDigest,
        Esys_GetSessionAuditDigest, Esys_GetTime, Esys_Quote,
    },
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

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

        let certify_info = Context::ffi_data_to_owned(certify_info_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
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

        let certify_info = Context::ffi_data_to_owned(certify_info_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
        Ok((
            Attest::try_from(AttestBuffer::try_from(certify_info)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Generate a quote on the selected PCRs
    ///
    /// # Arguments
    /// * `signing_key_handle`  - Handle of key that will perform signature.
    /// * `qualifying_data`     - Data supplied by the caller.
    /// * `signing_scheme`      - Signing scheme to use if the scheme for signing_key_handle is the null scheme.
    /// * `pcr_selection_list`  - The PCR set to quote.
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use tss_esapi::{Context, TctiNameConf};
    /// use std::convert::TryFrom;
    /// # use tss_esapi::{
    /// #     handles::KeyHandle,
    /// #     interface_types::{
    /// #         algorithm::{RsaSchemeAlgorithm, SignatureSchemeAlgorithm},
    /// #         key_bits::RsaKeyBits,
    /// #         reserved_handles::Hierarchy,
    /// #     },
    /// #     structures::{
    /// #         AttestInfo, RsaExponent, RsaScheme, Signature,
    /// #     },
    /// #     utils::{create_unrestricted_signing_rsa_public, create_restricted_decryption_rsa_public},
    /// # };
    /// use tss_esapi::{
    ///     interface_types::{
    ///         algorithm::HashingAlgorithm,
    ///         session_handles::AuthSession,
    ///     },
    ///     structures::{
    ///         Data, PcrSelectionListBuilder, PcrSlot, SignatureScheme,
    ///     },
    /// };
    ///
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let qualifying_data = Data::try_from(vec![0xff; 16])
    ///     .expect("It should be possible to create qualifying data from bytes.");
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
    ///
    /// // Quote PCR 0, 1, 2
    /// let pcr_selection_list = PcrSelectionListBuilder::new()
    ///     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot1, PcrSlot::Slot2])
    ///     .build()
    ///     .expect("It should be possible to create PCR selection list with valid values.");
    ///
    /// let (attest, signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             None,
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.quote(
    ///                 sign_key_handle,
    ///                 qualifying_data,
    ///                 SignatureScheme::Null,
    ///                 pcr_selection_list.clone(),
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to get quote");
    /// # match signature {
    /// #     Signature::RsaSsa(signature) => {
    /// #         assert_eq!(signature.hashing_algorithm(), HashingAlgorithm::Sha256);
    /// #     }
    /// #     _ => {
    /// #         panic!("Received the wrong signature from the call to `quote`.");
    /// #     }
    /// # }
    /// # match attest.attested() {
    /// #     AttestInfo::Quote { info } => {
    /// #         assert!(
    /// #             !info.pcr_digest().is_empty(),
    /// #             "Digest in QuoteInfo is empty"
    /// #         );
    /// #         assert_eq!(
    /// #             &pcr_selection_list,
    /// #             info.pcr_selection(),
    /// #             "QuoteInfo selection list did not match the input selection list"
    /// #         );
    /// #     }
    /// #     _ => {
    /// #         panic!("Attested did not contain the expected variant.")
    /// #     }
    /// # }
    /// ```
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
                    self.required_session_1()?,
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

        let quoted = Context::ffi_data_to_owned(quoted_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
        Ok((
            Attest::try_from(AttestBuffer::try_from(quoted)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Get the current time and clock from the TPM
    ///
    /// # Arguments
    /// * `signing_key_handle` - Handle of the key used to sign the attestation buffer
    /// * `qualifying_data` - Qualifying data
    /// * `signing_scheme` - Signing scheme to use if the scheme for `signing_key_handle` is `Null`.
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
    /// #     interface_types::{
    /// #         algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
    /// #         key_bits::RsaKeyBits,
    /// #         reserved_handles::Hierarchy,
    /// #     },
    /// #     structures::{
    /// #         RsaExponent, RsaScheme,
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
    /// let (attest, signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             Some(AuthSession::Password),
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.get_time(
    ///                 sign_key_handle,
    ///                 Data::try_from(qualifying_data).unwrap(),
    ///                 SignatureScheme::Null,
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to get tpm time");
    /// ```
    pub fn get_time(
        &mut self,
        signing_key_handle: KeyHandle,
        qualifying_data: Data,
        signing_scheme: SignatureScheme,
    ) -> Result<(Attest, Signature)> {
        let mut timeinfo_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_GetTime(
                    self.mut_context(),
                    ObjectHandle::Endorsement.into(),
                    signing_key_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &signing_scheme.into(),
                    &mut timeinfo_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error in GetTime: {:#010X}", ret);
            },
        )?;

        let timeinfo = Context::ffi_data_to_owned(timeinfo_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
        Ok((
            Attest::try_from(AttestBuffer::try_from(timeinfo)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Get a signed attestation of a session audit digest.
    ///
    /// # Arguments
    ///
    /// * `privacy_admin_handle` - An [ObjectHandle] for the privacy administrator (Endorsement).
    /// * `sign_handle` - A [KeyHandle] of the key used to sign the attestation.
    /// * `session_handle` - A [SessionHandle] of the session to be audited.
    /// * `qualifying_data` - [Data] to qualify the signing.
    /// * `signing_scheme` - The [SignatureScheme] to use.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command returns the current value of the session audit digest.
    ///
    /// # Returns
    ///
    /// A tuple of `(Attest, Signature)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::SessionAttributesBuilder,
    /// #    constants::SessionType,
    /// #    handles::{ObjectHandle, SessionHandle},
    /// #    interface_types::{
    /// #        algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #        session_handles::AuthSession,
    /// #    },
    /// #    structures::{Data, RsaExponent, RsaScheme, SignatureScheme, SymmetricDefinition},
    /// #    utils::create_unrestricted_signing_rsa_public,
    /// # };
    /// # use std::convert::TryFrom;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let signing_key_pub = create_unrestricted_signing_rsa_public(
    /// #         RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    /// #             .expect("Failed to create RSA scheme"),
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
    /// // Create an audit session
    /// let audit_session = context
    ///     .start_auth_session(
    ///         None, None, None,
    ///         SessionType::Hmac,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )
    ///     .expect("Failed to create audit session")
    ///     .expect("Received invalid handle");
    ///
    /// let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    ///     .with_audit(true)
    ///     .build();
    /// context
    ///     .tr_sess_set_attributes(audit_session, session_attributes, session_attributes_mask)
    ///     .expect("Failed to set audit attribute");
    ///
    /// // Use the audit session in a command to populate its digest
    /// context.set_sessions((Some(audit_session), None, None));
    /// let _ = context.read_public(sign_key_handle).unwrap();
    ///
    /// // Get the session audit digest
    /// let session_handle = SessionHandle::from(audit_session);
    /// let (_attest, _signature) = context
    ///     .execute_with_sessions(
    ///         (Some(AuthSession::Password), Some(AuthSession::Password), None),
    ///         |ctx| {
    ///             ctx.get_session_audit_digest(
    ///                 ObjectHandle::Endorsement,
    ///                 sign_key_handle,
    ///                 session_handle,
    ///                 Data::try_from(vec![0xff; 16]).unwrap(),
    ///                 SignatureScheme::Null,
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to get session audit digest");
    /// ```
    pub fn get_session_audit_digest(
        &mut self,
        privacy_admin_handle: ObjectHandle,
        sign_handle: KeyHandle,
        session_handle: SessionHandle,
        qualifying_data: Data,
        signing_scheme: SignatureScheme,
    ) -> Result<(Attest, Signature)> {
        let mut audit_info_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_GetSessionAuditDigest(
                    self.mut_context(),
                    privacy_admin_handle.into(),
                    sign_handle.into(),
                    session_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &signing_scheme.into(),
                    &mut audit_info_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error getting session audit digest: {:#010X}", ret);
            },
        )?;

        let audit_info = Context::ffi_data_to_owned(audit_info_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
        Ok((
            Attest::try_from(AttestBuffer::try_from(audit_info)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Get a signed attestation of the command audit digest.
    ///
    /// # Arguments
    ///
    /// * `privacy_handle` - An [ObjectHandle] for the privacy administrator (Endorsement).
    /// * `sign_handle` - A [KeyHandle] of the key used to sign the attestation.
    /// * `qualifying_data` - [Data] to qualify the signing.
    /// * `signing_scheme` - The [SignatureScheme] to use.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command returns the current value of the command audit digest,
    /// > a digest of the commands being audited, and the audit hash algorithm.
    ///
    /// # Returns
    ///
    /// A tuple of `(Attest, Signature)`.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    interface_types::{
    /// #        algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #        session_handles::AuthSession,
    /// #    },
    /// #    structures::{Data, RsaExponent, RsaScheme, SignatureScheme},
    /// #    utils::create_unrestricted_signing_rsa_public,
    /// # };
    /// # use std::convert::TryFrom;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let signing_key_pub = create_unrestricted_signing_rsa_public(
    /// #         RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    /// #             .expect("Failed to create RSA scheme"),
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
    /// let (_attest, _signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             Some(AuthSession::Password),
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.get_command_audit_digest(
    ///                 tss_esapi::handles::ObjectHandle::Endorsement,
    ///                 sign_key_handle,
    ///                 Data::try_from(vec![0xff; 16]).unwrap(),
    ///                 SignatureScheme::Null,
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to get command audit digest");
    /// ```
    pub fn get_command_audit_digest(
        &mut self,
        privacy_handle: ObjectHandle,
        sign_handle: KeyHandle,
        qualifying_data: Data,
        signing_scheme: SignatureScheme,
    ) -> Result<(Attest, Signature)> {
        let mut audit_info_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_GetCommandAuditDigest(
                    self.mut_context(),
                    privacy_handle.into(),
                    sign_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &qualifying_data.into(),
                    &signing_scheme.into(),
                    &mut audit_info_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error getting command audit digest: {:#010X}", ret);
            },
        )?;

        let audit_info = Context::ffi_data_to_owned(audit_info_ptr)?;
        let signature = Context::ffi_data_to_owned(signature_ptr)?;
        Ok((
            Attest::try_from(AttestBuffer::try_from(audit_info)?)?,
            Signature::try_from(signature)?,
        ))
    }

    /// Produce a signed X.509 certificate.
    ///
    /// # Arguments
    ///
    /// * `object_handle` - An [ObjectHandle] of the object to be certified.
    /// * `sign_handle` - A [KeyHandle] of the key used to sign the certificate.
    /// * `reserved` - Reserved for future use, should be an empty [Data].
    /// * `signing_scheme` - The [SignatureScheme] to use.
    /// * `partial_certificate` - A [MaxBuffer] containing the partial certificate.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > The purpose of this command is to generate an X.509 certificate that
    /// > proves an object with a specific public key and attributes is loaded
    /// > in the TPM.
    ///
    /// # Returns
    ///
    /// A tuple of `(MaxBuffer, Digest, Signature)`:
    ///
    /// * The [MaxBuffer] is a DER encoded SEQUENCE containing the DER encoded
    ///   fields added to `partial_certificate` to make it a complete RFC 5280
    ///   `TBSCertificate`.
    /// * The [Digest] is the TBS (to-be-signed) digest that was signed.
    /// * The [Signature] is the signature over the TBS digest.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::ObjectAttributesBuilder,
    /// #    handles::ObjectHandle,
    /// #    interface_types::{
    /// #        algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
    /// #        key_bits::RsaKeyBits,
    /// #        reserved_handles::Hierarchy,
    /// #        session_handles::AuthSession,
    /// #    },
    /// #    structures::{
    /// #        Data, MaxBuffer, PublicBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
    /// #        RsaExponent, RsaScheme, SignatureScheme,
    /// #    },
    /// # };
    /// # use std::convert::TryFrom;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(true)
    /// #     .with_x509_sign(true)
    /// #     .build()
    /// #     .expect("Failed to build object attributes");
    /// # let key_pub = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Rsa)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_rsa_parameters(
    /// #         PublicRsaParametersBuilder::new()
    /// #             .with_scheme(
    /// #                 RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    /// #                     .expect("Failed to create RSA scheme"),
    /// #             )
    /// #             .with_key_bits(RsaKeyBits::Rsa2048)
    /// #             .with_exponent(RsaExponent::default())
    /// #             .with_is_signing_key(true)
    /// #             .with_is_decryption_key(false)
    /// #             .with_restricted(true)
    /// #             .build()
    /// #             .expect("Failed to build RSA parameters"),
    /// #     )
    /// #     .with_rsa_unique_identifier(PublicKeyRsa::default())
    /// #     .build()
    /// #     .expect("Failed to build public");
    /// # let key_handle = context
    /// #     .execute_with_nullauth_session(|ctx| {
    /// #         ctx.create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
    /// #     })
    /// #     .unwrap()
    /// #     .key_handle;
    /// // DER-encoded partial X.509 certificate: SEQUENCE of
    /// //   { issuer, validity, subject, subjectPublicKeyInfo (placeholder),
    /// //     [3] EXPLICIT extensions }
    /// // The TPM prepends `version` and `serialNumber`, substitutes
    /// // `subjectPublicKeyInfo` with the certified key, then hashes / signs
    /// // the resulting TBSCertificate. This template encodes:
    /// //   issuer/subject : CN=rust-tss-esapi test
    /// //   validity       : 2020-01-01 .. 2040-01-01 (UTCTime)
    /// //   SPKI           : rsaEncryption OID + empty BIT STRING placeholder
    /// //   extensions     : keyUsage = digitalSignature | keyCertSign (critical)
    /// let partial_certificate: Vec<u8> = vec![
    ///     0x30, 0x81, 0x86, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04,
    ///     0x03, 0x0c, 0x13, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x74, 0x73, 0x73, 0x2d, 0x65,
    ///     0x73, 0x61, 0x70, 0x69, 0x20, 0x74, 0x65, 0x73, 0x74, 0x30, 0x1e, 0x17, 0x0d,
    ///     0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ///     0x17, 0x0d, 0x34, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30,
    ///     0x30, 0x5a, 0x30, 0x1e, 0x31, 0x1c, 0x30, 0x1a, 0x06, 0x03, 0x55, 0x04, 0x03,
    ///     0x0c, 0x13, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x74, 0x73, 0x73, 0x2d, 0x65, 0x73,
    ///     0x61, 0x70, 0x69, 0x20, 0x74, 0x65, 0x73, 0x74, 0x30, 0x10, 0x30, 0x0b, 0x06,
    ///     0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x03, 0x01, 0x00,
    ///     0xa3, 0x12, 0x30, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01,
    ///     0xff, 0x04, 0x04, 0x03, 0x02, 0x02, 0x84,
    /// ];
    ///
    /// let (_added, _tbs_digest, _signature) = context
    ///     .execute_with_sessions(
    ///         (
    ///             Some(AuthSession::Password),
    ///             Some(AuthSession::Password),
    ///             None,
    ///         ),
    ///         |ctx| {
    ///             ctx.certify_x509(
    ///                 ObjectHandle::from(key_handle),
    ///                 key_handle,
    ///                 Data::default(),
    ///                 SignatureScheme::Null,
    ///                 MaxBuffer::try_from(partial_certificate).unwrap(),
    ///             )
    ///         },
    ///     )
    ///     .expect("Failed to certify X.509");
    /// ```
    pub fn certify_x509(
        &mut self,
        object_handle: ObjectHandle,
        sign_handle: KeyHandle,
        reserved: Data,
        signing_scheme: SignatureScheme,
        partial_certificate: MaxBuffer,
    ) -> Result<(MaxBuffer, Digest, Signature)> {
        let mut added_to_certificate_ptr = null_mut();
        let mut tbs_digest_ptr = null_mut();
        let mut signature_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                // According to the ESAPI specification (Ver. 1, Rev. 14),
                // Esys_CertifyX509() only requires a sign handle session.
                // However, according to the TPM 2.0 Library spec (Ver. 185),
                // TPM2_CertifyX509() requires both object and sign handle
                // sessions. We suppose the latter to be correct.
                Esys_CertifyX509(
                    self.mut_context(),
                    object_handle.into(),
                    sign_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &reserved.into(),
                    &signing_scheme.into(),
                    &partial_certificate.into(),
                    &mut added_to_certificate_ptr,
                    &mut tbs_digest_ptr,
                    &mut signature_ptr,
                )
            },
            |ret| {
                error!("Error certifying X.509: {:#010X}", ret);
            },
        )?;

        Ok((
            MaxBuffer::try_from(Context::ffi_data_to_owned(added_to_certificate_ptr)?)?,
            Digest::try_from(Context::ffi_data_to_owned(tbs_digest_ptr)?)?,
            Signature::try_from(Context::ffi_data_to_owned(signature_ptr)?)?,
        ))
    }
}
