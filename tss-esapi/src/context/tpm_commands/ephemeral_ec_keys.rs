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
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Assumes sign_handle is a loaded ECC key with sign attribute set
    /// # // let (k, l, e, counter) = context.commit(sign_handle, None, None, None).unwrap();
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
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// use tss_esapi::interface_types::ecc::EccCurve;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// let (q_point, counter) = context.ec_ephemeral(EccCurve::NistP256).unwrap();
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
