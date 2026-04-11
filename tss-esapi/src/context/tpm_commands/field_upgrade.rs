// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::{AuthHandle, KeyHandle},
    structures::{Digest, HashAgile, MaxBuffer, Signature},
    tss2_esys::{Esys_FieldUpgradeData, Esys_FieldUpgradeStart, Esys_FirmwareRead},
};
use log::error;
use std::convert::TryFrom;
use std::ptr::null_mut;

impl Context {
    /// Start a field upgrade sequence.
    ///
    /// # Arguments
    ///
    /// * `authorization` - An [AuthHandle] for the platform hierarchy.
    /// * `key_handle` - A [KeyHandle] used to validate the manifest signature.
    /// * `fu_digest` - A [Digest] of the firmware upgrade data.
    /// * `manifest_signature` - A [Signature] over the fu_digest.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command uses platformPolicy and target key to authorize
    /// > a field upgrade.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Assumes authorization, key_handle, fu_digest, and manifest_signature
    /// # // are properly set up for a field upgrade operation.
    /// # // context.field_upgrade_start(authorization, key_handle, fu_digest, manifest_signature).unwrap();
    /// ```
    pub fn field_upgrade_start(
        &mut self,
        authorization: AuthHandle,
        key_handle: KeyHandle,
        fu_digest: Digest,
        manifest_signature: Signature,
    ) -> Result<()> {
        ReturnCode::ensure_success(
            unsafe {
                Esys_FieldUpgradeStart(
                    self.mut_context(),
                    authorization.into(),
                    key_handle.into(),
                    self.required_session_1()?,
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &fu_digest.into(),
                    &manifest_signature.try_into()?,
                )
            },
            |ret| {
                error!("Error starting field upgrade: {:#010X}", ret);
            },
        )
    }

    /// Send field upgrade data to the TPM.
    ///
    /// # Arguments
    ///
    /// * `fu_data` - A [MaxBuffer] containing the field upgrade data.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command will take the actual field upgrade image to be
    /// > installed on the TPM. The data is processed in a manner
    /// > that is determined by the TPM manufacturer.
    ///
    /// # Returns
    ///
    /// A tuple of `(HashAgile, HashAgile)` containing the next digest and first digest.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # use tss_esapi::structures::MaxBuffer;
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // Assumes a field upgrade sequence has been started
    /// # // let data = MaxBuffer::from_bytes(&[0x01, 0x02]).unwrap();
    /// # // let (next_digest, first_digest) = context.field_upgrade_data(data).unwrap();
    /// ```
    pub fn field_upgrade_data(&mut self, fu_data: MaxBuffer) -> Result<(HashAgile, HashAgile)> {
        let mut next_digest_ptr = null_mut();
        let mut first_digest_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_FieldUpgradeData(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    &fu_data.into(),
                    &mut next_digest_ptr,
                    &mut first_digest_ptr,
                )
            },
            |ret| {
                error!("Error sending field upgrade data: {:#010X}", ret);
            },
        )?;

        Ok((
            HashAgile::try_from(Context::ffi_data_to_owned(next_digest_ptr)?)?,
            HashAgile::try_from(Context::ffi_data_to_owned(first_digest_ptr)?)?,
        ))
    }

    /// Read the firmware data from the TPM.
    ///
    /// # Arguments
    ///
    /// * `sequence_number` - A `u32` sequence number for the firmware read.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to read a copy of the current firmware installed
    /// > in the TPM.
    ///
    /// # Returns
    ///
    /// A [MaxBuffer] containing the firmware data.
    ///
    /// # Example
    ///
    /// ```rust, no_run
    /// # use tss_esapi::{Context, TctiNameConf};
    /// # let mut context =
    /// #     Context::new(
    /// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// #     ).expect("Failed to create Context");
    /// # // context.firmware_read(0).unwrap();
    /// ```
    pub fn firmware_read(&mut self, sequence_number: u32) -> Result<MaxBuffer> {
        let mut fu_data_ptr = null_mut();
        ReturnCode::ensure_success(
            unsafe {
                Esys_FirmwareRead(
                    self.mut_context(),
                    self.optional_session_1(),
                    self.optional_session_2(),
                    self.optional_session_3(),
                    sequence_number,
                    &mut fu_data_ptr,
                )
            },
            |ret| {
                error!("Error reading firmware: {:#010X}", ret);
            },
        )?;
        MaxBuffer::try_from(Context::ffi_data_to_owned(fu_data_ptr)?)
    }
}
