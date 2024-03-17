// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
/// This module contains native representations of the TPMI_DH types.
use crate::{
    handles::{
        HmacSessionTpmHandle, NvIndexTpmHandle, PcrTpmHandle, PersistentTpmHandle,
        PolicySessionTpmHandle, TpmHandle, TransientTpmHandle,
    },
    tss2_esys::{TPMI_DH_CONTEXT, TPMI_DH_SAVED},
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

/// Enum representing the Persistent DH interface type
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
    fn from(persistent_tpm_handle: PersistentTpmHandle) -> Persistent {
        Persistent::Persistent(persistent_tpm_handle)
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
    // TODO: Handle Auth, that is vendor specific.
}

#[derive(Debug, Copy, Clone)]
pub enum Pcr {
    Pcr(PcrTpmHandle),
}

/// Enum representing the 'Context' data handles interface type.
///
/// # Details
/// This corresponds to the `TPMI_DH_CONTEXT` interface type. This only
/// exist for compatibility purposes the specification is not entirely
/// clear on whether this should still be used or be completely replaced by
/// [Saved].
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

/// Enum representing the 'Saved' data handles interface type.
///
/// # Details
/// This corresponds to the `TPMI_DH_SAVED` interface type.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Saved {
    /// A HMAC session context.
    Hmac(HmacSessionTpmHandle),
    /// A policy session context.
    Policy(PolicySessionTpmHandle),
    /// An ordinary transient object.
    Transient,
    /// A sequence object.
    Sequence,
    /// A transient object with stClear attribute SET.
    TransientClear,
}

impl From<HmacSessionTpmHandle> for Saved {
    fn from(hmac_session_tpm_handle: HmacSessionTpmHandle) -> Self {
        Saved::Hmac(hmac_session_tpm_handle)
    }
}

impl From<PolicySessionTpmHandle> for Saved {
    fn from(policy_session_tpm_handle: PolicySessionTpmHandle) -> Self {
        Saved::Policy(policy_session_tpm_handle)
    }
}

impl TryFrom<TransientTpmHandle> for Saved {
    type Error = Error;
    fn try_from(transient_tpm_handle: TransientTpmHandle) -> Result<Self> {
        match transient_tpm_handle {
            TransientTpmHandle::SavedTransient => Ok(Saved::Transient),
            TransientTpmHandle::SavedSequence => Ok(Saved::Sequence),
            TransientTpmHandle::SavedTransientClear => Ok(Saved::TransientClear),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TPMI_DH_SAVED> for Saved {
    type Error = Error;

    fn try_from(ffi: TPMI_DH_SAVED) -> Result<Self> {
        TpmHandle::try_from(ffi).and_then(|tpm_handle| match tpm_handle {
            TpmHandle::HmacSession(handle) => Ok(Self::Hmac(handle)),
            TpmHandle::PolicySession(handle) => Ok(Self::Policy(handle)),
            TpmHandle::Transient(handle) => Saved::try_from(handle),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        })
    }
}

impl From<Saved> for TPMI_DH_SAVED {
    fn from(native: Saved) -> TPMI_DH_SAVED {
        match native {
            Saved::Hmac(handle) => handle.into(),
            Saved::Policy(handle) => handle.into(),
            Saved::Transient => TransientTpmHandle::SavedTransient.into(),
            Saved::Sequence => TransientTpmHandle::SavedSequence.into(),
            Saved::TransientClear => TransientTpmHandle::SavedTransientClear.into(),
        }
    }
}
