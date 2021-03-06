// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::handles::{NvIndexTpmHandle, PcrTpmHandle, PersistentTpmHandle, TransientTpmHandle};

/// Can be created with either a persistant
/// or transient TPM handle.
#[derive(Debug, Copy, Clone)]
pub enum Object {
    Transient(TransientTpmHandle),
    Persistent(PersistentTpmHandle),
}

#[derive(Debug, Copy, Clone)]
pub enum Parent {
    Transient(TransientTpmHandle),
    Persistent(PersistentTpmHandle),
    Owner,
    Platform,
    Endorsement,
}

///
/// Enum representing the Persistant DH interface type
/// (TPMI_DH_PERSISTENT)
///
#[derive(Debug, Copy, Clone)]
pub enum Persistent {
    Persistent(PersistentTpmHandle),
}

impl From<Persistent> for PersistentTpmHandle {
    fn from(persistent: Persistent) -> PersistentTpmHandle {
        match persistent {
            Persistent::Persistent(val) => val,
        }
    }
}

impl From<PersistentTpmHandle> for Persistent {
    fn from(persistant_tpm_handle: PersistentTpmHandle) -> Persistent {
        Persistent::Persistent(persistant_tpm_handle)
    }
}

#[derive(Debug, Copy, Clone)]
pub enum Entity {
    Transient(TransientTpmHandle),
    Persistent(PersistentTpmHandle),
    Pcr(PcrTpmHandle),
    NvIndex(NvIndexTpmHandle),
    Owner,
    Platform,
    Endorsement,
    Lockout,
    // TODO: Handle Auth
}

#[derive(Debug, Copy, Clone)]
pub enum Pcr {
    Pcr(PcrTpmHandle),
}
