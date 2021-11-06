// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// The structures module attempts as far as possible to
/// reflect the specifcations way of defining structures
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
    attest::AttestBuffer,
    auth::Auth,
    data::Data,
    digest::Digest,
    ecc_parameter::EccParameter,
    encrypted_secret::EncryptedSecret,
    id_object::IDObject,
    initial_value::InitialValue,
    max_buffer::MaxBuffer,
    max_nv_buffer::MaxNvBuffer,
    nonce::Nonce,
    private::Private,
    public::{
        ecc::{PublicEccParameters, PublicEccParametersBuilder},
        keyed_hash::PublicKeyedHashParameters,
        rsa::{PublicRsaParameters, PublicRsaParametersBuilder, RsaExponent},
        Public, PublicBuilder,
    },
    public_key_rsa::PublicKeyRsa,
    sensitive_data::SensitiveData,
    timeout::Timeout,
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
pub use self::pcr_select::PcrSelect;
pub use self::pcr_select::PcrSelectSize;
pub use self::pcr_select::PcrSlot;
pub mod pcr_select {
    pub use super::pcr::select::*;
}

pub use self::pcr_selection::PcrSelection;
pub mod pcr_selection {
    pub use super::pcr::selection::*;
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
    schemes::{
        EccScheme, KeyDerivationFunctionScheme, KeyedHashScheme, RsaDecryptionScheme, RsaScheme,
        SignatureScheme,
    },
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
