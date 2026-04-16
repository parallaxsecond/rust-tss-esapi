// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::KeyHandle,
    interface_types::ecc::EccCurve,
    structures::{EccParameter, EccPoint, SensitiveData},
    tss2_esys::{Esys_Commit, Esys_EC_Ephemeral},
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null;
use std::ptr::null_mut;

impl Context {
    /// Perform an ECC commit to generate ephemeral key pair (K, L) and counter.
    ///
    /// # Arguments
    ///
    /// * `sign_handle` - A [KeyHandle] of the ECC key for which the commit is being generated.
    /// * `p1` - An optional point on the curve used by `sign_handle`.
    /// * `s2` - An optional octet array used in the commit computation.
    /// * `y2` - An optional ECC parameter used in the commit computation.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > TPM2_Commit() performs the first part of an ECC anonymous signing operation. The TPM will
    /// > perform the point multiplications on the provided points and return intermediate signing
    /// > values.
    ///
    /// > The TPM shall return TPM_RC_ATTRIBUTES if the sign attribute is not SET in the key
    /// > referenced by signHandle.
    ///
    /// # Returns
    ///
    /// A tuple of `(K, L, E, counter)` where K, L, E are [EccPoint] values
    /// and counter is a `u16` value to be used in the signing operation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tss_esapi::{
    /// #    Context, TctiNameConf,
    /// #    attributes::{SessionAttributesBuilder, ObjectAttributesBuilder},
    /// #    constants::SessionType,
    /// #    interface_types::{
    /// #        algorithm::{HashingAlgorithm, PublicAlgorithm},
    /// #        ecc::EccCurve,
    /// #        reserved_handles::Hierarchy,
    /// #   },
    /// #   structures::{
    /// #       Auth, EccPoint, EccScheme, KeyDerivationFunctionScheme,
    /// #       PublicBuilder, PublicEccParametersBuilder, SymmetricDefinition,
    /// #    },
    /// # };
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// #
    /// # let session = context
    /// #     .start_auth_session(
    /// #         None,
    /// #         None,
    /// #         None,
    /// #         SessionType::Hmac,
    /// #         SymmetricDefinition::AES_256_CFB,
    /// #         HashingAlgorithm::Sha256,
    /// #     )
    /// #     .expect("Failed to create session")
    /// #     .expect("Received invalid handle");
    /// # let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
    /// #     .with_decrypt(true)
    /// #     .with_encrypt(true)
    /// #     .build();
    /// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
    /// #     .expect("Failed to set attributes on session");
    /// # context.set_sessions((Some(session), None, None));
    /// # let mut random_digest = vec![0u8; 16];
    /// # getrandom::getrandom(&mut random_digest).expect("Failed to get random bytes");
    /// # let key_auth
    /// #     = Auth::from_bytes(random_digest.as_slice()).expect("Failed to create key auth");
    /// #
    /// # let ecc_parms = PublicEccParametersBuilder::new()
    /// #     .with_ecc_scheme(EccScheme::EcDaa(
    /// #         tss_esapi::structures::EcDaaScheme::new(HashingAlgorithm::Sha256, 0),
    /// #     ))
    /// #     .with_curve(EccCurve::BnP256)
    /// #     .with_is_signing_key(true)
    /// #     .with_is_decryption_key(false)
    /// #     .with_restricted(false)
    /// #     .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
    /// #     .build()
    /// #     .expect("Failed to build ECC parameters");
    /// #
    /// # let object_attributes = ObjectAttributesBuilder::new()
    /// #     .with_fixed_tpm(true)
    /// #     .with_fixed_parent(true)
    /// #     .with_sensitive_data_origin(true)
    /// #     .with_user_with_auth(true)
    /// #     .with_decrypt(false)
    /// #     .with_sign_encrypt(true)
    /// #     .with_restricted(false)
    /// #     .build()
    /// #     .expect("Failed to build object attributes");
    /// #
    /// # let public = PublicBuilder::new()
    /// #     .with_public_algorithm(PublicAlgorithm::Ecc)
    /// #     .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
    /// #     .with_object_attributes(object_attributes)
    /// #     .with_ecc_parameters(ecc_parms)
    /// #     .with_ecc_unique_identifier(EccPoint::default())
    /// #     .build()
    /// #     .expect("Failed to build public key");
    /// #
    /// # let key_handle = context
    /// #     .create_primary(Hierarchy::Owner, public, Some(key_auth), None, None, None)
    /// #     .expect("Failed to create primary key")
    /// #     .key_handle;
    /// let (_k, _l, _e, counter) = context
    ///     .commit(key_handle, EccPoint::default(), None, None)
    ///     .expect("Failed to perform ECC commit");
    /// ```
    pub fn commit(
        &mut self,
        sign_handle: KeyHandle,
        p1: impl Into<Option<EccPoint>>,
        s2: impl Into<Option<SensitiveData>>,
        y2: impl Into<Option<EccParameter>>,
    ) -> Result<(EccPoint, EccPoint, EccPoint, u16)> {
        let mut k_ptr = null_mut();
        let mut l_ptr = null_mut();
        let mut e_ptr = null_mut();
        let mut counter: u16 = 0;

        let potential_p1 = p1.into().map(|v| v.into());
        let p1_ptr = potential_p1.as_ref().map_or_else(null, std::ptr::from_ref);

        let potential_s2 = s2.into().map(|v| v.into());
        let s2_ptr = potential_s2.as_ref().map_or_else(null, std::ptr::from_ref);

        let potential_y2 = y2.into().map(|v| v.into());
        let y2_ptr = potential_y2.as_ref().map_or_else(null, std::ptr::from_ref);

        ReturnCode::ensure_success(
            unsafe {
                Esys_Commit(
                    self.mut_context(),
                    sign_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    p1_ptr,
                    s2_ptr,
                    y2_ptr,
                    &mut k_ptr,
                    &mut l_ptr,
                    &mut e_ptr,
                    &mut counter,
                )
            },
            |ret| {
                error!("Error when performing ECC commit: {:#010X}", ret);
            },
        )?;

        let k_point = Context::ffi_data_to_owned(k_ptr)?;
        let l_point = Context::ffi_data_to_owned(l_ptr)?;
        let e_point = Context::ffi_data_to_owned(e_ptr)?;
        Ok((
            EccPoint::try_from(k_point.point)?,
            EccPoint::try_from(l_point.point)?,
            EccPoint::try_from(e_point.point)?,
            counter,
        ))
    }

    /// Create an ephemeral ECC key.
    ///
    /// # Arguments
    ///
    /// * `curve` - An [EccCurve] specifying the curve for the ephemeral key.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > TPM2_EC_Ephemeral() creates an ephemeral key for use in a two-phase key exchange protocol.
    ///
    /// # Returns
    ///
    /// A tuple of `(Q, counter)` where Q is an [EccPoint] representing
    /// the public ephemeral key and counter is a `u16` to be used
    /// in a subsequent TPM2_Commit().
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// use tss_esapi::interface_types::ecc::EccCurve;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let (q_point, counter) = context
    ///     .ec_ephemeral(EccCurve::NistP256)
    ///     .expect("Failed to create EC ephemeral key");
    /// ```
    pub fn ec_ephemeral(&mut self, curve: EccCurve) -> Result<(EccPoint, u16)> {
        let mut q_ptr = null_mut();
        let mut counter: u16 = 0;

        ReturnCode::ensure_success(
            unsafe {
                Esys_EC_Ephemeral(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    curve.into(),
                    &mut q_ptr,
                    &mut counter,
                )
            },
            |ret| {
                error!("Error when creating EC ephemeral key: {:#010X}", ret);
            },
        )?;

        let q_point = Context::ffi_data_to_owned(q_ptr)?;
        Ok((EccPoint::try_from(q_point.point)?, counter))
    }
}
