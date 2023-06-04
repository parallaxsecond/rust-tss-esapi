// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use tss_esapi_sys::TPMI_ST_COMMAND_TAG;

use crate::{
    constants::StructureTag,
    traits::{Marshall, UnMarshall},
    tss2_esys::TPMI_ST_ATTEST,
    Error, Result, ReturnCode, WrapperErrorKind,
};
use std::convert::{TryFrom, TryInto};

/// Type of attestation.
///
/// # Details
/// Corresponds to `TPMI_ST_ATTEST`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationType {
    Certify,
    Quote,
    SessionAudit,
    CommandAudit,
    Time,
    Creation,
    Nv,
    NvDigest,
}

impl From<AttestationType> for StructureTag {
    fn from(native: AttestationType) -> Self {
        match native {
            AttestationType::Certify => StructureTag::AttestCertify,
            AttestationType::Quote => StructureTag::AttestQuote,
            AttestationType::SessionAudit => StructureTag::AttestSessionAudit,
            AttestationType::CommandAudit => StructureTag::AttestCommandAudit,
            AttestationType::Time => StructureTag::AttestTime,
            AttestationType::Creation => StructureTag::AttestCreation,
            AttestationType::Nv => StructureTag::AttestNv,
            AttestationType::NvDigest => StructureTag::AttestNvDigest,
        }
    }
}

impl TryFrom<StructureTag> for AttestationType {
    type Error = Error;

    fn try_from(structure_tag: StructureTag) -> Result<AttestationType> {
        match structure_tag {
            StructureTag::AttestCertify => Ok(AttestationType::Certify),
            StructureTag::AttestQuote => Ok(AttestationType::Quote),
            StructureTag::AttestSessionAudit => Ok(AttestationType::SessionAudit),
            StructureTag::AttestCommandAudit => Ok(AttestationType::CommandAudit),
            StructureTag::AttestTime => Ok(AttestationType::Time),
            StructureTag::AttestCreation => Ok(AttestationType::Creation),
            StructureTag::AttestNv => Ok(AttestationType::Nv),
            StructureTag::AttestNvDigest => Ok(AttestationType::NvDigest),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<AttestationType> for TPMI_ST_ATTEST {
    fn from(attestation_type: AttestationType) -> Self {
        StructureTag::from(attestation_type).into()
    }
}

impl TryFrom<TPMI_ST_ATTEST> for AttestationType {
    type Error = Error;

    fn try_from(tpmi_st_attest: TPMI_ST_ATTEST) -> Result<Self> {
        AttestationType::try_from(StructureTag::try_from(tpmi_st_attest)?)
    }
}

impl Marshall for AttestationType {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPMI_ST_ATTEST>();

    /// Produce a marshalled [`TPMI_ST_ATTEST`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2_ST_Marshal(
                    (*self).into(),
                    buffer.as_mut_ptr(),
                    Self::BUFFER_SIZE.try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                )
            },
            |ret| {
                error!("Failed to marshal AttestationType: {}", ret);
            },
        )?;

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for AttestationType {
    /// Unmarshall the structure from [`TPMI_ST_ATTEST`]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        AttestationType::unmarshall_offset(marshalled_data, &mut 0)
    }

    fn unmarshall_offset(
        marshalled_data: &[u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<Self> {
        let mut dest = TPMI_ST_ATTEST::default();

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2_ST_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal AttestationType: {}", ret),
        )?;

        AttestationType::try_from(dest)
    }
}

/// Type of command tag.
///
/// # Details
/// Corresponds to `TPMI_ST_COMMAND_TAG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandTag {
    Sessions,
    NoSessions,
}

impl From<CommandTag> for StructureTag {
    fn from(value: CommandTag) -> Self {
        match value {
            CommandTag::Sessions => StructureTag::Sessions,
            CommandTag::NoSessions => StructureTag::NoSessions,
        }
    }
}

impl TryFrom<StructureTag> for CommandTag {
    type Error = Error;

    fn try_from(value: StructureTag) -> std::result::Result<Self, Self::Error> {
        match value {
            StructureTag::Sessions => Ok(CommandTag::Sessions),
            StructureTag::NoSessions => Ok(CommandTag::NoSessions),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl From<CommandTag> for TPMI_ST_COMMAND_TAG {
    fn from(command_tag: CommandTag) -> Self {
        StructureTag::from(command_tag).into()
    }
}

impl TryFrom<TPMI_ST_COMMAND_TAG> for CommandTag {
    type Error = Error;

    fn try_from(tpmi_st_command_tag: TPMI_ST_COMMAND_TAG) -> Result<Self> {
        CommandTag::try_from(StructureTag::try_from(tpmi_st_command_tag)?)
    }
}

impl Marshall for CommandTag {
    const BUFFER_SIZE: usize = std::mem::size_of::<TPMI_ST_COMMAND_TAG>();

    /// Produce a marshalled [`TPMI_ST_COMMAND_TAG`]
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2_ST_Marshal(
                    (*self).into(),
                    buffer.as_mut_ptr(),
                    Self::BUFFER_SIZE.try_into().map_err(|e| {
                        error!("Failed to convert size of buffer to TSS size_t type: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    &mut offset,
                )
            },
            |ret| {
                error!("Failed to marshal CommandTag: {}", ret);
            },
        )?;

        let checked_offset = usize::try_from(offset).map_err(|e| {
            error!("Failed to parse offset as usize: {}", e);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })?;

        buffer.truncate(checked_offset);

        Ok(buffer)
    }
}

impl UnMarshall for CommandTag {
    /// Unmarshall the structure from [`TPMI_ST_COMMAND_TAG`]
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        CommandTag::unmarshall_offset(marshalled_data, &mut 0)
    }

    fn unmarshall_offset(
        marshalled_data: &[u8],
        offset: &mut std::os::raw::c_ulong,
    ) -> Result<Self> {
        let mut dest = TPMI_ST_COMMAND_TAG::default();

        ReturnCode::ensure_success(
            unsafe {
                crate::tss2_esys::Tss2_MU_TPM2_ST_Unmarshal(
                    marshalled_data.as_ptr(),
                    marshalled_data.len().try_into().map_err(|e| {
                        error!("Failed to convert length of marshalled data: {}", e);
                        Error::local_error(WrapperErrorKind::InvalidParam)
                    })?,
                    offset,
                    &mut dest,
                )
            },
            |ret| error!("Failed to unmarshal CommandTag: {}", ret),
        )?;

        CommandTag::try_from(dest)
    }
}
