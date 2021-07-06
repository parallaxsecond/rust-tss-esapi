// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::constants::tss::{
    TPM2_ST_ATTEST_CERTIFY, TPM2_ST_ATTEST_COMMAND_AUDIT, TPM2_ST_ATTEST_CREATION,
    TPM2_ST_ATTEST_NV, TPM2_ST_ATTEST_NV_DIGEST, TPM2_ST_ATTEST_QUOTE,
    TPM2_ST_ATTEST_SESSION_AUDIT, TPM2_ST_ATTEST_TIME,
};
use crate::constants::TPM_GENERATED_VALUE;
use crate::structures::{ClockInfo, Data, Name};
use crate::tss2_esys::{
    Tss2_MU_TPMS_ATTEST_Unmarshal, TPM2B_ATTEST, TPMI_ST_ATTEST, TPMS_ATTEST, TPMS_CERTIFY_INFO,
    TPMU_ATTEST,
};
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::convert::{TryFrom, TryInto};
use std::ops::Deref;
use zeroize::Zeroizing;

/// Object attestation structure
///
/// # Details
/// Corresponds to `TPMS_ATTEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attest {
    qualified_signer: Name,
    extra_data: Data,
    clock_info: ClockInfo,
    firmware_version: u64,
    attested: AttestInfo,
}

impl Attest {
    /// Get the type of attestation this was produced by.
    pub fn attestation_type(&self) -> AttestationType {
        self.attested.attestation_type()
    }

    /// Get the qualified name of the signing object.
    pub fn qualified_signer(&self) -> &Name {
        &self.qualified_signer
    }

    /// Get the extra data specified by the caller.
    pub fn extra_data(&self) -> &Data {
        &self.extra_data
    }

    /// Get internal TPM clock data.
    pub fn clock_info(&self) -> &ClockInfo {
        &self.clock_info
    }

    /// Get TPM firmware version number.
    pub fn firmware_version(&self) -> u64 {
        self.firmware_version
    }

    /// Get extra attestation information.
    pub fn attested(&self) -> &AttestInfo {
        &self.attested
    }
}

impl TryFrom<Attest> for TPMS_ATTEST {
    type Error = Error;

    fn try_from(native: Attest) -> Result<Self> {
        Ok(TPMS_ATTEST {
            magic: TPM_GENERATED_VALUE,
            type_: native.attestation_type().into(),
            qualifiedSigner: native.qualified_signer.try_into()?,
            extraData: native.extra_data.into(),
            clockInfo: native.clock_info.into(),
            firmwareVersion: native.firmware_version,
            attested: native.attested.try_into()?,
        })
    }
}

impl TryFrom<TPMS_ATTEST> for Attest {
    type Error = Error;

    fn try_from(tss: TPMS_ATTEST) -> Result<Self> {
        if tss.magic != TPM_GENERATED_VALUE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let attestation_type = AttestationType::try_from(tss.type_)?;
        Ok(Attest {
            attested: match attestation_type {
                AttestationType::Certify => AttestInfo::Certify {
                    name: Name::try_from(unsafe { tss.attested.certify.name })?,
                    qualified_name: Name::try_from(unsafe { tss.attested.certify.qualifiedName })?,
                },
                _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            },
            qualified_signer: Name::try_from(tss.qualifiedSigner)?,
            extra_data: Data::try_from(tss.extraData)?,
            clock_info: ClockInfo::try_from(tss.clockInfo)?,
            firmware_version: tss.firmwareVersion,
        })
    }
}

/// Representation of extra attestation data.
///
/// # Details
/// Corresponds to `TPMU_ATTEST`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttestInfo {
    Certify { name: Name, qualified_name: Name },
}

impl AttestInfo {
    /// Get the `AttestationType` variant that corresponds to the info.
    pub fn attestation_type(&self) -> AttestationType {
        match self {
            AttestInfo::Certify { .. } => AttestationType::Certify,
        }
    }
}

impl TryFrom<AttestInfo> for TPMU_ATTEST {
    type Error = Error;

    fn try_from(native: AttestInfo) -> Result<Self> {
        Ok(match native {
            AttestInfo::Certify {
                name,
                qualified_name,
            } => TPMU_ATTEST {
                certify: TPMS_CERTIFY_INFO {
                    name: name.try_into()?,
                    qualifiedName: qualified_name.try_into()?,
                },
            },
        })
    }
}

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

impl From<AttestationType> for TPMI_ST_ATTEST {
    fn from(native: AttestationType) -> Self {
        match native {
            AttestationType::Certify => TPM2_ST_ATTEST_CERTIFY,
            AttestationType::Quote => TPM2_ST_ATTEST_QUOTE,
            AttestationType::SessionAudit => TPM2_ST_ATTEST_SESSION_AUDIT,
            AttestationType::CommandAudit => TPM2_ST_ATTEST_COMMAND_AUDIT,
            AttestationType::Time => TPM2_ST_ATTEST_TIME,
            AttestationType::Creation => TPM2_ST_ATTEST_CREATION,
            AttestationType::Nv => TPM2_ST_ATTEST_NV,
            AttestationType::NvDigest => TPM2_ST_ATTEST_NV_DIGEST,
        }
    }
}

impl TryFrom<TPMI_ST_ATTEST> for AttestationType {
    type Error = Error;

    fn try_from(tss: TPMI_ST_ATTEST) -> Result<Self> {
        match tss {
            TPM2_ST_ATTEST_CERTIFY => Ok(AttestationType::Certify),
            TPM2_ST_ATTEST_QUOTE => Ok(AttestationType::Quote),
            TPM2_ST_ATTEST_TIME => Ok(AttestationType::Time),
            TPM2_ST_ATTEST_CREATION => Ok(AttestationType::Creation),
            TPM2_ST_ATTEST_NV => Ok(AttestationType::Nv),
            TPM2_ST_ATTEST_NV_DIGEST => Ok(AttestationType::NvDigest),
            TPM2_ST_ATTEST_SESSION_AUDIT => Ok(AttestationType::SessionAudit),
            TPM2_ST_ATTEST_COMMAND_AUDIT => Ok(AttestationType::CommandAudit),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

/// Attestation data buffer.
///
/// # Details
/// Corresponds to `TPM2B_ATTEST`. The contents of
/// the buffer can be unmarshalled into an [Attest]
/// structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestBuffer(Zeroizing<Vec<u8>>);

impl Default for AttestBuffer {
    fn default() -> Self {
        AttestBuffer(Vec::new().into())
    }
}

impl AttestBuffer {
    pub const MAX_SIZE: usize = 2304;

    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for AttestBuffer {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for AttestBuffer {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!("Error: Invalid Vec<u8> size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(bytes.into()))
    }
}

impl TryFrom<&[u8]> for AttestBuffer {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > Self::MAX_SIZE {
            error!("Error: Invalid &[u8] size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(bytes.to_vec().into()))
    }
}

impl TryFrom<TPM2B_ATTEST> for AttestBuffer {
    type Error = Error;

    fn try_from(tss: TPM2B_ATTEST) -> Result<Self> {
        let size = tss.size as usize;
        if size > Self::MAX_SIZE {
            error!("Error: Invalid buffer size(> {})", Self::MAX_SIZE);
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(AttestBuffer(tss.attestationData[..size].to_vec().into()))
    }
}

impl TryFrom<AttestBuffer> for Attest {
    type Error = Error;

    fn try_from(buf: AttestBuffer) -> Result<Self> {
        let buffer = buf.0.to_vec();
        let mut attest = TPMS_ATTEST::default();
        let buf_point: *const u8 = &buffer[0];
        let mut offset = 0;
        let ret = Error::from_tss_rc(unsafe {
            Tss2_MU_TPMS_ATTEST_Unmarshal(
                buf_point,
                buffer.len().try_into().unwrap(),
                &mut offset,
                &mut attest,
            )
        });

        if !ret.is_success() {
            return Err(ret);
        }
        Attest::try_from(attest)
    }
}

impl From<AttestBuffer> for TPM2B_ATTEST {
    fn from(native: AttestBuffer) -> Self {
        let mut buffer = TPM2B_ATTEST {
            size: native.0.len() as u16,
            ..Default::default()
        };
        buffer.attestationData[..native.0.len()].copy_from_slice(&native.0);
        buffer
    }
}
