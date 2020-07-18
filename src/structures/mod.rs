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
/// The names section
/////////////////////////////////////////////////////////
mod names;
pub use names::name::Name;
/////////////////////////////////////////////////////////
/// The sized buffers section
/////////////////////////////////////////////////////////
mod buffers;
pub use self::auth_buffer::Auth;
pub mod auth_buffer {
    pub use super::buffers::auth::*;
}

pub use self::digest_buffer::Digest;
pub mod digest_buffer {
    pub use super::buffers::digest::*;
}

pub use self::max_buffer::MaxBuffer;
pub mod max_buffer {
    pub use super::buffers::max::*;
}

pub use self::data_buffer::Data;
pub mod data_buffer {
    pub use super::buffers::data::*;
}

pub use self::nonce_buffer::Nonce;
pub mod nonce_buffer {
    pub use super::buffers::nonce::*;
}
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

pub use self::pcr_selection_list::PcrSelectionList;
pub use self::pcr_selection_list::PcrSelectionListBuilder;
pub mod pcr_selection_list {
    pub use super::lists::pcr_selection::*;
}
/////////////////////////////////////////////////////////
/// The tickets section
/////////////////////////////////////////////////////////
mod tickets;
pub use tickets::HashcheckTicket;
pub use tickets::Ticket;
pub use tickets::VerifiedTicket;
