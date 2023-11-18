/// This module contains native representations of the TPMI_DH types.
use crate::handles::{NvIndexTpmHandle, PcrTpmHandle, PersistentTpmHandle, TransientTpmHandle};

/// Enum representing the 'Object' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_OBJECT interface type.
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

/// Enum representing the 'Persistent' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_PERSISTENT interface type.
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
    fn from(persistent_tpm_handle: PersistentTpmHandle) -> Persistent {
        Persistent::Persistent(persistent_tpm_handle)
    }
}

/// Enum representing the 'Entity' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_ENTITY interface type.
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

/// Enum representing the 'PCR' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_PCR interface type.
#[derive(Debug, Copy, Clone)]
pub enum Pcr {
    Pcr(PcrTpmHandle),
}
