use crate::constants::{
    TPM2_ST_ATTEST_CERTIFY, TPM2_ST_ATTEST_COMMAND_AUDIT, TPM2_ST_ATTEST_CREATION,
    TPM2_ST_ATTEST_NV, TPM2_ST_ATTEST_NV_DIGEST, TPM2_ST_ATTEST_QUOTE,
    TPM2_ST_ATTEST_SESSION_AUDIT, TPM2_ST_ATTEST_TIME, TPM2_ST_AUTH_SECRET, TPM2_ST_AUTH_SIGNED,
    TPM2_ST_CREATION, TPM2_ST_FU_MANIFEST, TPM2_ST_HASHCHECK, TPM2_ST_NO_SESSIONS, TPM2_ST_NULL,
    TPM2_ST_RESERVED1, TPM2_ST_RESERVED2, TPM2_ST_RESERVED3, TPM2_ST_RSP_COMMAND, TPM2_ST_SESSIONS,
    TPM2_ST_VERIFIED,
};
use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::TPM2_ST;
use std::convert::{From, TryFrom};

/// This enum represents the TPM_ST (Structure Tags)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructureTag {
    RspCommand,
    Null,
    NoSessions,
    Sessions,
    Reserved1,
    Reserved2,
    AttestNv,
    AttestCommandAudit,
    AttestSessionAudit,
    AttestCertify,
    AttestQuote,
    AttestTime,
    AttestCreation,
    AttestNvDigest,
    Creation,
    Verified,
    AuthSecret,
    Hashcheck,
    AuthSigned,
    FuManifest,
}

impl From<StructureTag> for TPM2_ST {
    fn from(structure_tag: StructureTag) -> Self {
        match structure_tag {
            StructureTag::RspCommand => TPM2_ST_RSP_COMMAND,
            StructureTag::Null => TPM2_ST_NULL,
            StructureTag::NoSessions => TPM2_ST_NO_SESSIONS,
            StructureTag::Sessions => TPM2_ST_SESSIONS,
            StructureTag::Reserved1 => TPM2_ST_RESERVED1,
            StructureTag::Reserved2 => TPM2_ST_RESERVED2,
            StructureTag::AttestNv => TPM2_ST_ATTEST_NV,
            StructureTag::AttestCommandAudit => TPM2_ST_ATTEST_COMMAND_AUDIT,
            StructureTag::AttestSessionAudit => TPM2_ST_ATTEST_SESSION_AUDIT,
            StructureTag::AttestCertify => TPM2_ST_ATTEST_CERTIFY,
            StructureTag::AttestQuote => TPM2_ST_ATTEST_QUOTE,
            StructureTag::AttestTime => TPM2_ST_ATTEST_TIME,
            StructureTag::AttestCreation => TPM2_ST_ATTEST_CREATION,
            StructureTag::AttestNvDigest => TPM2_ST_ATTEST_NV_DIGEST,
            StructureTag::Creation => TPM2_ST_CREATION,
            StructureTag::Verified => TPM2_ST_VERIFIED,
            StructureTag::AuthSecret => TPM2_ST_AUTH_SECRET,
            StructureTag::Hashcheck => TPM2_ST_HASHCHECK,
            StructureTag::AuthSigned => TPM2_ST_AUTH_SIGNED,
            StructureTag::FuManifest => TPM2_ST_FU_MANIFEST,
        }
    }
}

impl TryFrom<TPM2_ST> for StructureTag {
    type Error = Error;
    fn try_from(tpm2_structure_tag: TPM2_ST) -> Result<Self> {
        match tpm2_structure_tag {
            TPM2_ST_RSP_COMMAND => Ok(StructureTag::RspCommand),
            TPM2_ST_NULL => Ok(StructureTag::Null),
            TPM2_ST_NO_SESSIONS => Ok(StructureTag::NoSessions),
            TPM2_ST_SESSIONS => Ok(StructureTag::Sessions),
            TPM2_ST_RESERVED1 => Ok(StructureTag::Reserved1),
            TPM2_ST_RESERVED2 => Ok(StructureTag::Reserved2),
            TPM2_ST_ATTEST_NV => Ok(StructureTag::AttestNv),
            TPM2_ST_ATTEST_COMMAND_AUDIT => Ok(StructureTag::AttestCommandAudit),
            TPM2_ST_ATTEST_SESSION_AUDIT => Ok(StructureTag::AttestSessionAudit),
            TPM2_ST_ATTEST_CERTIFY => Ok(StructureTag::AttestCertify),
            TPM2_ST_ATTEST_QUOTE => Ok(StructureTag::AttestQuote),
            TPM2_ST_ATTEST_TIME => Ok(StructureTag::AttestTime),
            TPM2_ST_ATTEST_CREATION => Ok(StructureTag::AttestCreation),
            TPM2_ST_RESERVED3 => Err(Error::local_error(WrapperErrorKind::InvalidParam)), /* Spec: "DO NOT USE. This was previously assigned to TPM_ST_ATTEST_NV. The tag is changed because the structure has changed" */
            TPM2_ST_ATTEST_NV_DIGEST => Ok(StructureTag::AttestNvDigest),
            TPM2_ST_CREATION => Ok(StructureTag::Creation),
            TPM2_ST_VERIFIED => Ok(StructureTag::Verified),
            TPM2_ST_AUTH_SECRET => Ok(StructureTag::AuthSecret),
            TPM2_ST_HASHCHECK => Ok(StructureTag::Hashcheck),
            TPM2_ST_AUTH_SIGNED => Ok(StructureTag::AuthSigned),
            TPM2_ST_FU_MANIFEST => Ok(StructureTag::FuManifest),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
