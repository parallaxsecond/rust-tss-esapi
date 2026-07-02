// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    handles::KeyHandle,
    interface_types::YesNo,
    structures::{CreationData, CreationTicket, Digest, Private, Public},
};

#[allow(missing_debug_implementations)]
pub struct CreateKeyResult {
    pub out_private: Private,
    pub out_public: Public,
    pub creation_data: CreationData,
    pub creation_hash: Digest,
    pub creation_ticket: CreationTicket,
}

#[allow(missing_debug_implementations)]
pub struct CreatePrimaryKeyResult {
    pub key_handle: KeyHandle,
    pub out_public: Public,
    pub creation_data: CreationData,
    pub creation_hash: Digest,
    pub creation_ticket: CreationTicket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrAllocateResult {
    /// YES if the allocation succeeded.
    pub allocation_success: YesNo,
    /// Maximum number of PCR that may be in a bank.
    pub max_pcr: u32,
    /// Number of octets required to satisfy the request.
    pub size_needed: u32,
    /// Number of octets available. Computed before the allocation.
    pub size_available: u32,
}
