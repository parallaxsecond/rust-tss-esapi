// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// The structures module attempts as far as possible to
/// reflect the specifications way of defining structures
/// see:
///
/// Trusted Platform Module Library
/// Part 2: Structures
/// Family “2.0”
/// Level 00 Revision 01.59
/// November 8, 2019
/// Published
///
/// Chapter 10: Structure Definitions

/////////////////////////////////////////////////////////
/// The capabilitydata section
/////////////////////////////////////////////////////////
mod capabilitydata;
pub use self::capabilitydata::CapabilityData;
/////////////////////////////////////////////////////////
/// The names section
/////////////////////////////////////////////////////////
mod names;
pub use names::name::Name;
/////////////////////////////////////////////////////////
/// The result section
/////////////////////////////////////////////////////////
mod result;
pub use result::CreateKeyResult;
pub use result::CreatePrimaryKeyResult;
/////////////////////////////////////////////////////////
/// The sized buffers section
/////////////////////////////////////////////////////////
mod buffers;
pub use self::buffers::{
    attest::AttestBuffer, auth::Auth, data::Data, digest::Digest, ecc_parameter::EccParameter,
    encrypted_secret::EncryptedSecret, id_object::IdObject, initial_value::InitialValue,
    max_buffer::MaxBuffer, max_nv_buffer::MaxNvBuffer, nonce::Nonce, private::Private,
    private_key_rsa::PrivateKeyRsa, private_vendor_specific::PrivateVendorSpecific,
    public::PublicBuffer, public_key_rsa::PublicKeyRsa, sensitive::SensitiveBuffer,
    sensitive_data::SensitiveData, symmetric_key::SymmetricKey, timeout::Timeout,
};
/////////////////////////////////////////////////////////
/// The creation section
/////////////////////////////////////////////////////////
mod creation;
pub use self::creation::CreationData;
/////////////////////////////////////////////////////////
/// The hash section
/////////////////////////////////////////////////////////
mod hash;
pub use self::hash::agile::HashAgile;
/////////////////////////////////////////////////////////
/// The pcr section
/////////////////////////////////////////////////////////
mod pcr;

pub use self::pcr_slot::PcrSlot;
pub mod pcr_slot {
    pub use super::pcr::slot::*;
}

pub use self::pcr_select::PcrSelect;
pub mod pcr_select {
    pub use super::pcr::select::*;
}

pub use self::pcr_selection::PcrSelection;
pub mod pcr_selection {
    pub use super::pcr::selection::*;
}

pub use self::pcr_select_size::PcrSelectSize;
pub mod pcr_select_size {
    pub use super::pcr::select_size::*;
}
/////////////////////////////////////////////////////////
/// The lists section
/////////////////////////////////////////////////////////
mod lists;
pub use self::digest_list::DigestList;
pub mod digest_list {
    pub use super::lists::digest::*;
}

pub use self::digest_values::DigestValues;
pub mod digest_values {
    pub use super::lists::digest_values::*;
}

pub use self::pcr_selection_list::PcrSelectionList;
pub use self::pcr_selection_list::PcrSelectionListBuilder;
pub mod pcr_selection_list {
    pub use super::lists::pcr_selection::*;
}

pub use self::command_code_list::CommandCodeList;
pub mod command_code_list {
    pub use super::lists::command_code::*;
}

pub use self::tagged_tpm_property_list::TaggedTpmPropertyList;
pub mod tagged_tpm_property_list {
    pub use super::lists::tagged_tpm_property::*;
}

pub use algorithm_property_list::AlgorithmPropertyList;
pub mod algorithm_property_list {
    pub use super::lists::algorithm_property::*;
}
/////////////////////////////////////////////////////////
/// The parameters section
/////////////////////////////////////////////////////////
mod parameters;
pub use self::parameters::SymmetricCipherParameters;
/////////////////////////////////////////////////////////
/// The tickets section
/////////////////////////////////////////////////////////
mod tickets;
pub use tickets::AuthTicket;
pub use tickets::CreationTicket;
pub use tickets::HashcheckTicket;
pub use tickets::Ticket;
pub use tickets::VerifiedTicket;

mod schemes;
pub use schemes::{EcDaaScheme, HashScheme, HmacScheme, XorScheme};

mod tagged;
pub use tagged::{
    parameters::PublicParameters,
    public::{
        ecc::{PublicEccParameters, PublicEccParametersBuilder},
        keyed_hash::PublicKeyedHashParameters,
        rsa::{PublicRsaParameters, PublicRsaParametersBuilder, RsaExponent},
        Public, PublicBuilder,
    },
    schemes::{
        EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, RsaDecryptionScheme, RsaScheme,
        SignatureScheme,
    },
    sensitive::Sensitive,
    signature::Signature,
    symmetric::{SymmetricDefinition, SymmetricDefinitionObject},
};
/////////////////////////////////////////////////////////
/// ECC structures
/////////////////////////////////////////////////////////
mod ecc;
pub use ecc::point::EccPoint;
/////////////////////////////////////////////////////////
/// Signatures structures
/////////////////////////////////////////////////////////
mod signatures;
pub use signatures::{EccSignature, RsaSignature};
/////////////////////////////////////////////////////////
/// Clock info
/////////////////////////////////////////////////////////
mod clock_info;
pub use clock_info::ClockInfo;
/////////////////////////////////////////////////////////
/// Certify Info
/////////////////////////////////////////////////////////
mod certify_info;
pub use certify_info::CertifyInfo;
/////////////////////////////////////////////////////////
/// Quote Info
/////////////////////////////////////////////////////////
mod quote_info;
pub use quote_info::QuoteInfo;
/////////////////////////////////////////////////////////
/// Time Info
/////////////////////////////////////////////////////////
mod time_info;
pub use time_info::TimeInfo;
/////////////////////////////////////////////////////////
/// Time Attest Info
/////////////////////////////////////////////////////////
mod time_attest_info;
pub use time_attest_info::TimeAttestInfo;
/////////////////////////////////////////////////////////
/// Command Audit Info
/////////////////////////////////////////////////////////
mod command_audit_info;
pub use command_audit_info::CommandAuditInfo;
/////////////////////////////////////////////////////////
/// Session Audit Info
/////////////////////////////////////////////////////////
mod session_audit_info;
pub use session_audit_info::SessionAuditInfo;
/////////////////////////////////////////////////////////
/// Creation Info
/////////////////////////////////////////////////////////
mod creation_info;
pub use creation_info::CreationInfo;
/////////////////////////////////////////////////////////
/// Nv Certify Info
/////////////////////////////////////////////////////////
mod nv_certify_info;
pub use nv_certify_info::NvCertifyInfo;
/////////////////////////////////////////////////////////
/// Nv Digest Certify Info
/////////////////////////////////////////////////////////
mod nv_digest_certify_info;
pub use nv_digest_certify_info::NvDigestCertifyInfo;
/////////////////////////////////////////////////////////
/// Attest Info
/////////////////////////////////////////////////////////
mod attest_info;
pub use attest_info::AttestInfo;
/////////////////////////////////////////////////////////
/// Attest
/////////////////////////////////////////////////////////
mod attest;
pub use attest::Attest;
/// Tagged Property
/////////////////////////////////////////////////////////
mod tagged_property;
pub use tagged_property::TaggedProperty;
/////////////////////////////////////////////////////////
/// AlgorithmProperty
/////////////////////////////////////////////////////////
mod algorithm_property;
pub use algorithm_property::AlgorithmProperty;
/////////////////////////////////////////////////////////
/// TaggedPcrSelect
/////////////////////////////////////////////////////////
mod tagged_pcr_select;
pub use tagged_pcr_select::TaggedPcrSelect;
