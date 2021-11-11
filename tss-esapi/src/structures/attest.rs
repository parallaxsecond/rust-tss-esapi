// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::tss::TPM2_GENERATED_VALUE,
    interface_types::structure_tags::AttestationType,
    structures::{AttestInfo, ClockInfo, Data, Name},
    tss2_esys::TPMS_ATTEST,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Type for holding attestation data
///
/// # Details
/// Corresponds to `TPMS_ATTEST`.
#[derive(Debug, Clone)]
pub struct Attest {
    attestation_type: AttestationType,
    qualified_signer: Name,
    extra_data: Data,
    clock_info: ClockInfo,
    firmware_version: u64,
    attested: AttestInfo,
}

impl Attest {
    /// Returns ttestation type
    pub const fn attestation_type(&self) -> AttestationType {
        self.attestation_type
    }

    /// Returns the qualified name of the signing object.
    pub const fn qualified_signer(&self) -> &Name {
        &self.qualified_signer
    }

    /// Retirns the extra data specified by the caller.
    pub const fn extra_data(&self) -> &Data {
        &self.extra_data
    }

    /// Returns the internal TPM clock data.
    pub const fn clock_info(&self) -> &ClockInfo {
        &self.clock_info
    }

    /// Returns TPM firmware version number.
    pub const fn firmware_version(&self) -> u64 {
        self.firmware_version
    }

    /// Returns types specific attestation information
    pub const fn attested(&self) -> &AttestInfo {
        &self.attested
    }
}

impl From<Attest> for TPMS_ATTEST {
    fn from(attest: Attest) -> Self {
        TPMS_ATTEST {
            magic: TPM2_GENERATED_VALUE,
            type_: attest.attestation_type.into(),
            qualifiedSigner: attest.qualified_signer.into(),
            extraData: attest.extra_data.into(),
            clockInfo: attest.clock_info.into(),
            firmwareVersion: attest.firmware_version,
            attested: attest.attested.into(),
        }
    }
}

impl TryFrom<TPMS_ATTEST> for Attest {
    type Error = Error;

    fn try_from(tpms_attest: TPMS_ATTEST) -> Result<Self> {
        if tpms_attest.magic != TPM2_GENERATED_VALUE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let attestation_type = AttestationType::try_from(tpms_attest.type_)?;
        Ok(Attest {
            attestation_type,
            qualified_signer: Name::try_from(tpms_attest.qualifiedSigner)?,
            extra_data: Data::try_from(tpms_attest.extraData)?,
            clock_info: ClockInfo::try_from(tpms_attest.clockInfo)?,
            firmware_version: tpms_attest.firmwareVersion,
            attested: match attestation_type {
                AttestationType::Certify => AttestInfo::Certify {
                    info: unsafe { tpms_attest.attested.certify }.try_into()?,
                },
                AttestationType::Quote => AttestInfo::Quote {
                    info: unsafe { tpms_attest.attested.quote }.try_into()?,
                },
                AttestationType::SessionAudit => AttestInfo::SessionAudit {
                    info: unsafe { tpms_attest.attested.sessionAudit }.try_into()?,
                },
                AttestationType::CommandAudit => AttestInfo::CommandAudit {
                    info: unsafe { tpms_attest.attested.commandAudit }.try_into()?,
                },
                AttestationType::Time => AttestInfo::Time {
                    info: unsafe { tpms_attest.attested.time }.try_into()?,
                },
                AttestationType::Creation => AttestInfo::Creation {
                    info: unsafe { tpms_attest.attested.creation }.try_into()?,
                },
                AttestationType::Nv => AttestInfo::Nv {
                    info: unsafe { tpms_attest.attested.nv }.try_into()?,
                },
                AttestationType::NvDigest => {
                    error!("NvDigest attestation type is currently not supported");
                    return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
                }
            },
        })
    }
}
