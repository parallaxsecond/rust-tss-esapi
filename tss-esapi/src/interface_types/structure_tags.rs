// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi_sys::TPMI_ST_COMMAND_TAG;

use crate::{
    constants::StructureTag, traits::impl_mu_simple, tss2_esys::TPMI_ST_ATTEST, Error, Result,
    WrapperErrorKind,
};
use std::convert::TryFrom;

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

impl_mu_simple!(AttestationType, TPMI_ST_ATTEST, TPM2_ST);

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

impl_mu_simple!(CommandTag, TPMI_ST_COMMAND_TAG, TPM2_ST);
