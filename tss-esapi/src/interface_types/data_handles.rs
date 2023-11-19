/// This module contains native representations of the TPMI_DH types.
use crate::{
    handles::{
        HmacSessionTpmHandle, NvIndexTpmHandle, PcrTpmHandle, PersistentTpmHandle,
        PolicySessionTpmHandle, TpmHandle, TransientTpmHandle,
    },
    tss2_esys::TPMI_DH_CONTEXT,
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
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
    // TODO: Handle Auth, that is vendor specific.
}

/// Enum representing the 'PCR' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_PCR interface type.
#[derive(Debug, Copy, Clone)]
pub enum Pcr {
    Pcr(PcrTpmHandle),
}

/// Enum representing the 'Context' data handles interface type.
///
/// # Details
/// This corresponds to the TPMI_DH_CONTEXT interface type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ContextDataHandle {
    Hmac(HmacSessionTpmHandle),
    Policy(PolicySessionTpmHandle),
    Transient(TransientTpmHandle),
}

impl From<HmacSessionTpmHandle> for ContextDataHandle {
    fn from(hmac_session_tpm_handle: HmacSessionTpmHandle) -> Self {
        ContextDataHandle::Hmac(hmac_session_tpm_handle)
    }
}

impl From<PolicySessionTpmHandle> for ContextDataHandle {
    fn from(policy_session_tpm_handle: PolicySessionTpmHandle) -> Self {
        ContextDataHandle::Policy(policy_session_tpm_handle)
    }
}

impl From<TransientTpmHandle> for ContextDataHandle {
    fn from(transient_tpm_handle: TransientTpmHandle) -> Self {
        ContextDataHandle::Transient(transient_tpm_handle)
    }
}

impl TryFrom<TPMI_DH_CONTEXT> for ContextDataHandle {
    type Error = Error;

    fn try_from(ffi: TPMI_DH_CONTEXT) -> Result<Self> {
        TpmHandle::try_from(ffi).and_then(|tpm_handle| match tpm_handle {
            TpmHandle::HmacSession(handle) => Ok(Self::Hmac(handle)),
            TpmHandle::PolicySession(handle) => Ok(Self::Policy(handle)),
            TpmHandle::Transient(handle) => Ok(Self::Transient(handle)),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        })
    }
}
