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
pub use self::buffers::auth::Auth;

pub use self::buffers::digest::Digest;

pub use self::buffers::max_buffer::MaxBuffer;

pub use self::buffers::max_nv_buffer::MaxNvBuffer;

pub use self::buffers::data::Data;

pub use self::buffers::id_object::IDObject;

pub use self::buffers::encrypted_secret::EncryptedSecret;

pub use self::buffers::sensitive_data::SensitiveData;

pub use self::buffers::private::Private;

pub use self::buffers::public_key_rsa::PublicKeyRSA;

pub use self::buffers::nonce::Nonce;

pub use self::buffers::timeout::Timeout;
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
pub use self::parameters::KeyedHashParms;
/////////////////////////////////////////////////////////
/// The tickets section
/////////////////////////////////////////////////////////
mod tickets;
pub use tickets::AuthTicket;
pub use tickets::CreationTicket;
pub use tickets::HashcheckTicket;
pub use tickets::Ticket;
pub use tickets::VerifiedTicket;
