// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::{ObjectHandle, PcrHandle, TpmHandle},
    interface_types::algorithm::HashingAlgorithm,
    interface_types::reserved_handles::Hierarchy,
    structures::{Auth, Digest, DigestValues, HashcheckTicket, MaxBuffer},
    tss2_esys::{
        Esys_EventSequenceComplete, Esys_HMAC_Start, Esys_HashSequenceStart, Esys_SequenceComplete,
        Esys_SequenceUpdate,
    },
};
use log::error;
use std::ptr::null_mut;

impl Context {
    /// Starts HMAC sequence of large data (larger than [`MaxBuffer::MAX_SIZE`]) using the specified algorithm.
    ///
    /// # Details
    /// When the amount of data to be included in a digest cannot be sent to the TPM in one atomic HMAC
    /// command then a sequence of commands may be used to provide incremental updates to the digest.
    ///
    /// Follow the pattern:
    ///  - Initialize sequence with [`Context::hmac_sequence_start`]
    ///  - Send data to calculate the hash with [`Context::sequence_update`]
    ///  - Finish hash calculation with call to [`Context::sequence_complete`]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, tcti_ldr::TctiNameConf,
    /// #     attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    /// #     structures::{
    /// #         Auth, MaxBuffer, Ticket, SymmetricDefinition,
    /// #         RsaExponent, RsaScheme, KeyedHashScheme,
    /// #         PublicBuilder, PublicKeyedHashParameters
    /// #     },
    /// #     constants::{
    /// #         tss::{TPMA_SESSION_DECRYPT, TPMA_SESSION_ENCRYPT},
    /// #         SessionType,
    /// #     },
    /// #     interface_types::{
    /// #         algorithm::{HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm},
    /// #         key_bits::RsaKeyBits, reserved_handles::Hierarchy
    /// #     },
    /// #     utils::create_unrestricted_signing_rsa_public,
    /// # };
    /// # use std::convert::TryFrom;
    /// # use std::str::FromStr;
    /// # // Create context with session
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let session = context
    /// #    .start_auth_session(
    /// #        None,
    /// #        None,
    /// #        None,
    /// #        SessionType::Hmac,
    /// #        SymmetricDefinition::AES_256_CFB,
    /// #        HashingAlgorithm::Sha256,
    /// #    )
    /// #    .expect("Failed to create session");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #    .with_decrypt(true)
    /// #    .with_encrypt(true)
    /// #    .build();
    /// # context.tr_sess_set_attributes(session.unwrap(), session_attributes, session_attributes_mask)
    /// #    .expect("Failed to set attributes on session");
    /// # context.set_sessions((session, None, None));
    /// #
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_sign_encrypt(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .build()
    ///     .expect("Failed to build object attributes");
    ///
    /// let key_pub = PublicBuilder::new()
    ///     .with_public_algorithm(PublicAlgorithm::KeyedHash)
    ///     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    ///     .with_object_attributes(object_attributes)
    ///     .with_keyed_hash_parameters(PublicKeyedHashParameters::new(
    ///         KeyedHashScheme::HMAC_SHA_256,
    ///     ))
    ///     .with_keyed_hash_unique_identifier(Default::default())
    ///     .build()
    ///     .expect("Failed to build public structure for key.");
    ///
    /// let key = context
    ///     .create_primary(Hierarchy::Owner, key_pub, None, None, None, None)
    ///     .unwrap();
    ///
    /// let data = [0xEE; 5000];
    ///
    /// let handle = context
    ///     .hmac_sequence_start(key.key_handle.into(), HashingAlgorithm::Sha256, None)
    ///     .unwrap();
    ///
    /// let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
    /// let last_chunk = chunks.remainder();
    /// for chunk in chunks {
    ///     context
    ///         .sequence_update(handle, MaxBuffer::from_bytes(chunk).unwrap())
    ///         .unwrap();
    /// }
    /// let (actual_hashed_data, ticket) = context
    ///     .sequence_complete(
    ///         handle,
    ///         MaxBuffer::from_bytes(last_chunk).unwrap(),
    ///         Hierarchy::Null,
    ///     )
    ///    .unwrap();
    /// ```
    pub fn hmac_sequence_start(
        &mut self,
        handle: ObjectHandle,
        hashing_algorithm: HashingAlgorithm,
        auth: Option<Auth>,
    ) -> Result<ObjectHandle> {
        let mut sequence_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_HMAC_Start(
                    self.mut_context(),
                    handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.unwrap_or_default().into(),
                    hashing_algorithm.into(),
                    &mut sequence_handle,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform HMAC sequence start operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok(ObjectHandle::from(sequence_handle))
    }

    // Missing function: MAC (requires TPMI_ALG_MAC_SCHEME wrapper)
    // Missing function: MAC_Start (requires TPMI_ALG_MAC_SCHEME wrapper)

    /// Starts hash sequence of large data (larger than [`MaxBuffer::MAX_SIZE`]) using the specified algorithm.
    ///
    /// # Details
    /// When the amount of data to be included in a digest cannot be sent to the TPM in one atomic hash
    /// command then a sequence of commands may be used to provide incremental updates to the digest.
    ///
    /// Follow the pattern:
    ///  - Initialize sequence with [`Context::hmac_sequence_start`]
    ///  - Send data to calculate the hash with [`Context::sequence_update`]
    ///  - Finish hash calculation with call to [`Context::sequence_complete`]
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, tcti_ldr::TctiNameConf,
    /// #     attributes::SessionAttributesBuilder,
    /// #     structures::{Auth, MaxBuffer, Ticket, SymmetricDefinition, RsaExponent, RsaScheme},
    /// #     constants::{
    /// #         tss::{TPMA_SESSION_DECRYPT, TPMA_SESSION_ENCRYPT},
    /// #         SessionType,
    /// #     },
    /// #     interface_types::{
    /// #         algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
    /// #         key_bits::RsaKeyBits, reserved_handles::Hierarchy
    /// #     },
    /// #     utils::create_unrestricted_signing_rsa_public,
    /// # };
    /// # use std::convert::TryFrom;
    /// # use std::str::FromStr;
    /// # // Create context with session
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let session = context
    /// #    .start_auth_session(
    /// #        None,
    /// #        None,
    /// #        None,
    /// #        SessionType::Hmac,
    /// #        SymmetricDefinition::AES_256_CFB,
    /// #        HashingAlgorithm::Sha256,
    /// #    )
    /// #    .expect("Failed to create session");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #    .with_decrypt(true)
    /// #    .with_encrypt(true)
    /// #    .build();
    /// # context.tr_sess_set_attributes(session.unwrap(), session_attributes, session_attributes_mask)
    /// #    .expect("Failed to set attributes on session");
    /// # context.set_sessions((session, None, None));
    ///
    /// let data = [0xEE; 2*1025];
    ///
    /// let handle = context
    ///     .hash_sequence_start(HashingAlgorithm::Sha256, None)
    ///     .unwrap();
    ///
    /// let chunks = data.chunks_exact(MaxBuffer::MAX_SIZE);
    /// let last_chunk = chunks.remainder();
    /// for chunk in chunks {
    ///     context
    ///         .sequence_update(handle, MaxBuffer::from_bytes(chunk).unwrap())
    ///         .unwrap();
    /// }
    /// let (actual_hashed_data, ticket) = context
    ///      .sequence_complete(
    ///         handle,
    ///         MaxBuffer::from_bytes(last_chunk).unwrap(),
    ///         Hierarchy::Owner,
    ///     )
    ///     .unwrap();
    /// ```
    pub fn hash_sequence_start(
        &mut self,
        hashing_algorithm: HashingAlgorithm,
        auth: Option<Auth>,
    ) -> Result<ObjectHandle> {
        let mut sequence_handle = ObjectHandle::None.into();
        ReturnCode::ensure_success(
            unsafe {
                Esys_HashSequenceStart(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &auth.unwrap_or_default().into(),
                    hashing_algorithm.into(),
                    &mut sequence_handle,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform hash sequence start operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok(ObjectHandle::from(sequence_handle))
    }

    /// Continues hash or HMAC sequence.
    ///
    /// See [`Context::hash_sequence_start`], [`Context::hmac_sequence_start`].
    pub fn sequence_update(
        &mut self,
        sequence_handle: ObjectHandle,
        data: MaxBuffer,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_SequenceUpdate(
                    self.mut_context(),
                    sequence_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &data.into(),
                )
            },
            |ret| {
                error!(
                    "Error failed to perform sequence update operation: {:#010X}",
                    ret
                );
            },
        )
    }

    /// Finishes hash or HMAC sequence.
    ///
    /// /// See [`Context::hash_sequence_start`], [`Context::hmac_sequence_start`].
    pub fn sequence_complete(
        &mut self,
        sequence_handle: ObjectHandle,
        data: MaxBuffer,
        hierarchy: Hierarchy,
    ) -> Result<(Digest, Option<HashcheckTicket>)> {
        let mut out_hash_ptr = null_mut();
        let mut validation_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_SequenceComplete(
                    self.mut_context(),
                    sequence_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &data.into(),
                    if cfg!(hierarchy_is_esys_tr) {
                        ObjectHandle::from(hierarchy).into()
                    } else {
                        TpmHandle::from(hierarchy).into()
                    },
                    &mut out_hash_ptr,
                    &mut validation_ptr,
                )
            },
            |ret| {
                error!(
                    "Error failed to perform sequence complete operation: {:#010X}",
                    ret
                );
            },
        )?;
        Ok((
            Digest::try_from(Context::ffi_data_to_owned(out_hash_ptr)?)?,
            if validation_ptr.is_null() {
                // For HMAC sequence validation parameter is NULL
                None
            } else {
                Some(HashcheckTicket::try_from(Context::ffi_data_to_owned(
                    validation_ptr,
                )?)?)
            },
        ))
    }

    /// Complete an event sequence and extend a PCR.
    ///
    /// # Arguments
    ///
    /// * `pcr_handle` - A [PcrHandle] of the PCR to extend.
    /// * `sequence_handle` - An [ObjectHandle] of the sequence to complete.
    /// * `buffer` - A [MaxBuffer] containing the last data to include.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command adds the last part of data, if any, to a hash/HMAC sequence
    /// > and returns the result. It also extends a PCR with the hash result.
    ///
    /// # Returns
    ///
    /// A [DigestValues] containing the digests computed over the event data.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::handles::PcrHandle;
    /// # use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    /// # use tss_esapi::structures::MaxBuffer;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # let handle = context.hash_sequence_start(HashingAlgorithm::Null, None).unwrap();
    /// let data = MaxBuffer::from_bytes(&[1, 2, 3]).unwrap();
    /// let digests = context.event_sequence_complete(PcrHandle::Pcr16, handle, data).unwrap();
    /// ```
    pub fn event_sequence_complete(
        &mut self,
        pcr_handle: PcrHandle,
        sequence_handle: ObjectHandle,
        buffer: MaxBuffer,
    ) -> Result<DigestValues> {
        let mut results_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_EventSequenceComplete(
                    self.mut_context(),
                    pcr_handle.into(),
                    sequence_handle.into(),
                    self.required_session_1()?,
                    self.required_session_2()?,
                    self.optional_session_3(),
                    &buffer.into(),
                    &mut results_ptr,
                )
            },
            |ret| {
                error!("Error completing event sequence: {:#010X}", ret);
            },
        )?;
        let results = Context::ffi_data_to_owned(results_ptr)?;
        let mut digest_values = DigestValues::new();
        for i in 0..results.count as usize {
            let tpmt_ha = results.digests[i];
            let algorithm = HashingAlgorithm::try_from(tpmt_ha.hashAlg)?;
            let digest = match algorithm {
                HashingAlgorithm::Sha1 => Digest::from(unsafe { tpmt_ha.digest.sha1 }),
                HashingAlgorithm::Sha256 => Digest::from(unsafe { tpmt_ha.digest.sha256 }),
                HashingAlgorithm::Sha384 => Digest::from(unsafe { tpmt_ha.digest.sha384 }),
                HashingAlgorithm::Sha512 => Digest::from(unsafe { tpmt_ha.digest.sha512 }),
                HashingAlgorithm::Sm3_256 => Digest::from(unsafe { tpmt_ha.digest.sm3_256 }),
                _ => {
                    return Err(crate::Error::local_error(
                        crate::WrapperErrorKind::WrongValueFromTpm,
                    ));
                }
            };
            digest_values.set(algorithm, digest);
        }
        Ok(digest_values)
    }
}
