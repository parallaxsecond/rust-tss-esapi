// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    Context, Result, ReturnCode,
    handles::{AuthHandle, KeyHandle},
    interface_types::algorithm::HashingAlgorithm,
    structures::{Digest, HashAgile, MaxBuffer, Signature},
    tss2_esys::{Esys_FieldUpgradeData, Esys_FieldUpgradeStart, Esys_FirmwareRead},
};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ptr::null_mut;

impl Context {
    /// Authorizes and starts a field-upgrade sequence.
    ///
    /// If the platform authorization and manifest signature are valid, the TPM enters Field
    /// Upgrade Mode and begins accepting data through [Self::field_upgrade_data].
    ///
    /// # Arguments
    ///
    /// * `authorization` - The [AuthHandle::Platform] handle. Its platform policy authorizes the
    ///   upgrade.
    /// * `key_handle` - A [KeyHandle] referencing the loaded TPM vendor authorization public key.
    /// * `fu_digest` - Digest of the first field-upgrade data block.
    /// * `manifest_signature` - TPM vendor signature over `fu_digest`.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > TPM2_FieldUpgradeStart() validates that a signature on the provided digest is from the
    /// > TPM manufacturer, and that proper authorization is provided using platformPolicy. If the
    /// > proper authorization is given, the TPM will retain the signed digest and enter the Field
    /// > Upgrade mode (FUM).
    ///
    /// # Example
    ///
    /// Starting an authorized field upgrade changes TPM firmware state, so this example is not
    /// executed automatically.
    ///
    /// ```rust,no_run
    /// use tss_esapi::{
    ///     handles::{AuthHandle, KeyHandle},
    ///     interface_types::session_handles::AuthSession,
    ///     structures::{Digest, Signature},
    ///     Context, Result,
    /// };
    ///
    /// fn start_field_upgrade(
    ///     context: &mut Context,
    ///     platform_authorization: AuthSession,
    ///     vendor_key_handle: KeyHandle,
    ///     first_block_digest: Digest,
    ///     manifest_signature: Signature,
    /// ) -> Result<()> {
    ///     context.execute_with_session(Some(platform_authorization), |ctx| {
    ///         ctx.field_upgrade_start(
    ///             AuthHandle::Platform,
    ///             vendor_key_handle,
    ///             first_block_digest,
    ///             manifest_signature,
    ///         )
    ///     })
    /// }
    /// ```
    pub fn field_upgrade_start(
        &mut self,
        authorization: AuthHandle,
        key_handle: KeyHandle,
        fu_digest: Digest,
        manifest_signature: Signature,
    ) -> Result<()> {
        let manifest_signature = manifest_signature.try_into()?;
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
                    &manifest_signature,
                )
            },
            |ret| {
                error!("Error failed to start field upgrade: {:#010X}", ret);
            },
        )
    }

    /// Supplies a block of vendor-specific firmware data during a field-upgrade sequence.
    ///
    /// This command can only succeed after [Self::field_upgrade_start]. The TPM validates the
    /// block against its expected digest before buffering or applying it.
    ///
    /// # Arguments
    ///
    /// * `fu_data` - The next vendor-specific field-upgrade data block.
    ///
    /// # Returns
    ///
    /// A pair containing the expected digest of the next block and the digest of the first block.
    /// When the upgrade is complete, the first value has [HashingAlgorithm::Null] as its hashing
    /// algorithm.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command will take the actual field upgrade image to be installed on the TPM. The
    /// > exact format of fuData is vendor-specific. This command is only possible following a
    /// > successful TPM2_FieldUpgradeStart(). If the TPM has not received a properly authorized
    /// > TPM2_FieldUpgradeStart(), then the TPM shall return TPM_RC_FIELDUPGRADE.
    ///
    /// # Example
    ///
    /// Supplying an accepted block may replace or augment TPM firmware, so this example is not
    /// executed automatically.
    ///
    /// ```rust,no_run
    /// use tss_esapi::{
    ///     interface_types::algorithm::HashingAlgorithm,
    ///     structures::{HashAgile, MaxBuffer},
    ///     Context, Result,
    /// };
    ///
    /// fn send_field_upgrade_block(
    ///     context: &mut Context,
    ///     block: MaxBuffer,
    /// ) -> Result<(HashAgile, HashAgile)> {
    ///     let (next_digest, first_digest) = context.field_upgrade_data(block)?;
    ///     if next_digest.hashing_algorithm() == HashingAlgorithm::Null {
    ///         println!("The field upgrade is complete");
    ///     }
    ///     Ok((next_digest, first_digest))
    /// }
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
                error!("Error failed to send field upgrade data: {:#010X}", ret);
            },
        )?;

        let next_digest = Context::ffi_data_to_owned(next_digest_ptr)?;
        let first_digest = Context::ffi_data_to_owned(first_digest_ptr)?;
        let next_digest =
            if HashingAlgorithm::try_from(next_digest.hashAlg)? == HashingAlgorithm::Null {
                HashAgile::new(HashingAlgorithm::Null, Digest::default())
            } else {
                HashAgile::try_from(next_digest)?
            };

        Ok((next_digest, HashAgile::try_from(first_digest)?))
    }

    /// Reads one block from a copy of the TPM's currently installed firmware.
    ///
    /// Start with sequence number zero and increment it for subsequent calls. An empty returned
    /// buffer marks the end of the sequence. Support for this command is optional.
    ///
    /// # Arguments
    ///
    /// * `sequence_number` - The number of previous calls in the current read sequence.
    ///
    /// # Returns
    ///
    /// An opaque block of firmware data, or an empty [MaxBuffer] at the end of the sequence.
    ///
    /// # Details
    ///
    /// *From the specification*
    /// > This command is used to read a copy of the current firmware installed in the TPM.
    ///
    /// # Example
    ///
    /// ```rust
    /// use tss_esapi::{Context, TctiNameConf};
    ///
    /// let mut context = Context::new(
    ///     TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
    /// )
    /// .expect("Failed to create Context");
    ///
    /// match context.firmware_read(0) {
    ///     Ok(first_block) if first_block.is_empty() => println!("The firmware image is empty"),
    ///     Ok(first_block) => println!("Read {} firmware bytes", first_block.len()),
    ///     Err(error) => eprintln!("Firmware reading is not supported: {error}"),
    /// }
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
                error!("Error failed to read firmware: {:#010X}", ret);
            },
        )?;
        MaxBuffer::try_from(Context::ffi_data_to_owned(fu_data_ptr)?)
    }
}
