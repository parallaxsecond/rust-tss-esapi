use crate::{
    constants::algorithm::HashingAlgorithm,
    handles::{ObjectHandle, TpmHandle},
    interface_types::resource_handles::Hierarchy,
    structures::{Digest, HashcheckTicket, MaxBuffer},
    tss2_esys::*,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    // Missing function: EncryptDecrypt
    // Missing function: EncryptDecrypt2

    /// Hashes the provided data using the specified algorithm.
    ///
    /// # Details
    /// Performs the specified hash operation on a data buffer and return
    /// the result. The HashCheckTicket indicates if the hash can be used in
    /// a signing operation that uses restricted signing key.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{Context, Tcti,
    /// #     structures::{MaxBuffer, Ticket},
    /// #     constants::algorithm::HashingAlgorithm,
    /// #     interface_types::resource_handles::Hierarchy,
    /// # };
    /// # use std::convert::TryFrom;
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// let input_data = MaxBuffer::try_from("There is no spoon".as_bytes().to_vec())
    ///     .expect("Failed to create buffer for input data.");
    /// let expected_hashed_data: [u8; 32] = [
    ///     0x6b, 0x38, 0x4d, 0x2b, 0xfb, 0x0e, 0x0d, 0xfb, 0x64, 0x89, 0xdb, 0xf4, 0xf8, 0xe9,
    ///     0xe5, 0x2f, 0x71, 0xee, 0xb1, 0x0d, 0x06, 0x4c, 0x56, 0x59, 0x70, 0xcd, 0xd9, 0x44,
    ///     0x43, 0x18, 0x5d, 0xc1,
    /// ];
    /// let expected_hierarchy = Hierarchy::Owner;
    /// let (actual_hashed_data, ticket) = context
    ///     .hash(
    ///         &input_data,
    ///         HashingAlgorithm::Sha256,
    ///         expected_hierarchy,
    ///     )
    ///     .expect("Call to hash failed.");
    /// assert_eq!(expected_hashed_data.len(), actual_hashed_data.len());
    /// assert_eq!(&expected_hashed_data[..], &actual_hashed_data[..]);
    /// assert_eq!(ticket.hierarchy(), expected_hierarchy);
    /// ```
    pub fn hash(
        &mut self,
        data: &MaxBuffer,
        hashing_algorithm: HashingAlgorithm,
        hierarchy: Hierarchy,
    ) -> Result<(Digest, HashcheckTicket)> {
        let mut out_hash_ptr = null_mut();
        let mut validation_ptr = null_mut();
        let ret = unsafe {
            Esys_Hash(
                self.mut_context(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &data.clone().into(),
                hashing_algorithm.into(),
                if cfg!(tpm2_tss_version = "3") {
                    ObjectHandle::from(hierarchy).into()
                } else {
                    TpmHandle::from(hierarchy).into()
                },
                &mut out_hash_ptr,
                &mut validation_ptr,
            )
        };
        let ret = Error::from_tss_rc(ret);
        if ret.is_success() {
            let out_hash = unsafe { MBox::<TPM2B_DIGEST>::from_raw(out_hash_ptr) };
            let validation = unsafe { MBox::<TPMT_TK_HASHCHECK>::from_raw(validation_ptr) };
            Ok((
                Digest::try_from(*out_hash)?,
                HashcheckTicket::try_from(*validation)?,
            ))
        } else {
            error!("Error failed to peform hash operation: {}", ret);
            Err(ret)
        }
    }

    /// Asks the TPM to compute an HMAC over buffer with the specified key
    ///
    /// # Example
    ///
    /// ```rust
    /// # use tss_esapi::{
    /// #     attributes::ObjectAttributesBuilder,
    /// #     structures::{MaxBuffer, Ticket, KeyedHashParms},
    /// #     constants::algorithm::HashingAlgorithm,
    /// #     interface_types::resource_handles::Hierarchy,
    /// #     constants::tss::{TPM2_ALG_KEYEDHASH, TPM2_ALG_SHA256},
    /// #     utils::{Tpm2BPublicBuilder, PublicParmsUnion},
    /// #     Context, Tcti,
    /// # };
    /// # use std::convert::TryFrom;
    /// # // Create context
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// // Create a key
    /// let object_attributes = ObjectAttributesBuilder::new()
    ///     .with_sign_encrypt(true)
    ///     .with_sensitive_data_origin(true)
    ///     .with_user_with_auth(true)
    ///     .build()
    ///     .expect("Failed to build object attributes");
    /// let key_pub = Tpm2BPublicBuilder::new()
    ///     .with_type(TPM2_ALG_KEYEDHASH)
    ///     .with_name_alg(TPM2_ALG_SHA256)
    ///     .with_parms(PublicParmsUnion::KeyedHashDetail(KeyedHashParms::HMAC {
    ///         hash_alg: HashingAlgorithm::Sha256,
    ///     }))
    ///     .with_object_attributes(object_attributes)
    ///     .build()
    ///     .unwrap();
    ///
    /// let input_data = MaxBuffer::try_from("There is no spoon".as_bytes().to_vec())
    ///     .expect("Failed to create buffer for input data.");
    ///
    /// let hmac = context.execute_with_nullauth_session(|ctx| {
    ///     let key = ctx.create_primary(Hierarchy::Owner, &key_pub, None, None, None, None).unwrap();
    ///
    ///     ctx.hmac(key.key_handle.into(), &input_data, HashingAlgorithm::Sha256)
    /// }).unwrap();
    ///
    /// ```
    ///
    /// # Errors
    /// * if any of the public parameters is not compatible with the TPM,
    /// an `Err` containing the specific unmarshalling error will be returned.
    pub fn hmac(
        &mut self,
        handle: ObjectHandle,
        buffer: &MaxBuffer,
        alg_hash: HashingAlgorithm,
    ) -> Result<Digest> {
        let mut out_digest = null_mut();

        let ret = unsafe {
            Esys_HMAC(
                self.mut_context(),
                handle.into(),
                self.required_session_1()?,
                self.optional_session_2(),
                self.optional_session_3(),
                &buffer.clone().into(),
                alg_hash.into(),
                &mut out_digest,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let out_digest = unsafe { MBox::from_raw(out_digest) };
            Ok(Digest::try_from(*out_digest)?)
        } else {
            error!("Error in hmac: {}", ret);
            Err(ret)
        }
    }

    // Missing function: MAC
}
