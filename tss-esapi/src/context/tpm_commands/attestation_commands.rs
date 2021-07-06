// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{KeyHandle, ObjectHandle},
    structures::{AttestBuffer, Data, PcrSelectionList, SignatureScheme},
    tss2_esys::{Esys_Certify, Esys_Quote, TPM2B_ATTEST, TPMT_SIG_SCHEME},
    utils::Signature,
    Context, Error, Result,
};
use log::error;
use mbox::MBox;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Certify that an object is resident in the TPM.
    ///
    /// # Arguments
    /// * `object_handle` - The object to be certified
    /// * `signing_key_handle` - The key to be used for signing the
    /// attestation structure.
    /// * `qualifying_data` - Data provided by the caller, generally
    /// to ensure freshness of the attestation.
    /// * `scheme` - Signature scheme to be used with the signing key.
    ///
    /// # Example
    /// ```rust,no_run
    /// # use std::convert::{TryFrom, TryInto};
    /// # use tss_esapi::{
    /// #   Context, Error, Tcti,
    /// #   handles::KeyHandle,
    /// #   structures::Auth,
    /// #   tss2_esys::TPM2B_PUBLIC,
    /// # };
    /// # fn main() -> Result<(), Error> {
    /// # let mut context = unsafe {
    /// #     Context::new(
    /// #         Tcti::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context")
    /// # };
    /// # let authentication_value = Auth::try_from(vec![0xff; 16]).unwrap();
    /// # let primary_key_handle: KeyHandle = 0.try_into().unwrap();
    /// # let attesting_key: KeyHandle = 1.try_into().unwrap();
    /// # let challenge = vec![0; 8];
    /// # let pub_params = TPM2B_PUBLIC::default();
    /// use tss_esapi::{
    ///     constants::SessionType,
    ///     interface_types::algorithm::HashingAlgorithm,
    ///     structures::{SymmetricDefinition, SignatureScheme, Data},
    /// };
    /// // Generate the key to be attested
    /// let result = context
    ///     .create(
    ///         primary_key_handle,
    ///         &pub_params,
    ///         Some(&authentication_value),
    ///         None,
    ///         None,
    ///         None,
    ///     )?;
    /// let attested_key = context
    ///     .load(primary_key_handle, result.out_private, result.out_public)?;
    /// // Create sessions for authenticating the two objects
    /// let obj_session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )?
    ///     .expect("Failed to create session for certified object authentication");
    /// let sign_session = context
    ///     .start_auth_session(
    ///         None,
    ///         None,
    ///         None,
    ///         SessionType::Hmac,
    ///         SymmetricDefinition::AES_256_CFB,
    ///         HashingAlgorithm::Sha256,
    ///     )?
    ///     .expect("Failed to create session for signing key authentication");
    ///
    /// // Convert `challenge` byte vector to `Data`
    /// let qualifying_data = Data::try_from(challenge).unwrap();
    ///
    /// // Execute `certify()` with the new sessions.
    /// let (attest_buffer, signature) = context.execute_with_sessions((Some(obj_session), Some(sign_session), None), |ctx| {
    ///     ctx
    ///     .certify(
    ///         attested_key.into(),
    ///         attesting_key, // restricted signing key
    ///         qualifying_data,
    ///         SignatureScheme::NULL, // use default signing scheme
    ///     )
    /// })?;
    /// # Ok(())
    /// # } // end main() fn
    pub fn certify(
        &mut self,
        object_handle: ObjectHandle,
        signing_key_handle: KeyHandle,
        qualifying_data: Data,
        scheme: SignatureScheme,
    ) -> Result<(AttestBuffer, Signature)> {
        let mut signature = null_mut();
        let mut certify_info = null_mut();
        let ret = unsafe {
            Esys_Certify(
                self.mut_context(),
                object_handle.into(),
                signing_key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &qualifying_data.into(),
                &scheme.into(),
                &mut certify_info,
                &mut signature,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let signature = unsafe { MBox::from_raw(signature) };
            let certify_info = unsafe { MBox::from_raw(certify_info) };
            Ok(unsafe {
                (
                    AttestBuffer::try_from(*certify_info)?,
                    Signature::try_from(*signature)?,
                )
            })
        } else {
            error!("Error when certifying: {}", ret);
            Err(ret)
        }
    }

    // Missing function: CertifyCreation

    /// Generate a quote on the selected PCRs
    ///
    /// # Errors
    /// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
    pub fn quote(
        &mut self,
        signing_key_handle: KeyHandle,
        qualifying_data: &Data,
        signing_scheme: TPMT_SIG_SCHEME,
        pcr_selection_list: PcrSelectionList,
    ) -> Result<(TPM2B_ATTEST, Signature)> {
        let mut quoted = null_mut();
        let mut signature = null_mut();
        let ret = unsafe {
            Esys_Quote(
                self.mut_context(),
                signing_key_handle.into(),
                self.optional_session_1(),
                self.optional_session_2(),
                self.optional_session_3(),
                &qualifying_data.clone().into(),
                &signing_scheme,
                &pcr_selection_list.into(),
                &mut quoted,
                &mut signature,
            )
        };
        let ret = Error::from_tss_rc(ret);

        if ret.is_success() {
            let quoted = unsafe { MBox::<TPM2B_ATTEST>::from_raw(quoted) };
            let signature = unsafe { MBox::from_raw(signature) };
            Ok((*quoted, unsafe { Signature::try_from(*signature)? }))
        } else {
            error!("Error in quoting PCR: {}", ret);
            Err(ret)
        }
    }

    // Missing function: GetSessionAuditDigest
    // Missing function: GestCommandAuditDigest
    // Missing function: GetTime
    // Missing function: CertifyX509
}
