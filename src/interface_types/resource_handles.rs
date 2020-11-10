// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_RH_ENDORSEMENT, TPM2_RH_LOCKOUT, TPM2_RH_NULL, TPM2_RH_OWNER, TPM2_RH_PLATFORM,
        TPM2_RH_PLATFORM_NV,
    },
    handles::{
        AttachedComponentTpmHandle, AuthHandle, NvIndexHandle, NvIndexTpmHandle, TpmConstantsHandle,
    },
    tss2_esys::{
        ESYS_TR, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL, ESYS_TR_RH_OWNER,
        ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV, TPM2_HANDLE, TPM2_RH, TPMI_RH_HIERARCHY,
    },
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
//////////////////////////////////////////////////////////////////////////////////
/// Hierarchy
///
/// Enum describing the object hierarchies in a TPM 2.0.
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hierarchy {
    Owner,
    Platform,
    Endorsement,
    Null,
}

impl Hierarchy {
    /// Get the ESYS resource handle for the hierarchy.
    pub fn esys_rh(self) -> TPMI_RH_HIERARCHY {
        match self {
            Hierarchy::Owner => ESYS_TR_RH_OWNER,
            Hierarchy::Platform => ESYS_TR_RH_PLATFORM,
            Hierarchy::Endorsement => ESYS_TR_RH_ENDORSEMENT,
            Hierarchy::Null => ESYS_TR_RH_NULL,
        }
    }

    /// Get the TPM resource handle for the hierarchy.
    pub fn rh(self) -> TPM2_RH {
        match self {
            Hierarchy::Owner => TPM2_RH_OWNER,
            Hierarchy::Platform => TPM2_RH_PLATFORM,
            Hierarchy::Endorsement => TPM2_RH_ENDORSEMENT,
            Hierarchy::Null => TPM2_RH_NULL,
        }
    }
}

impl TryFrom<TPM2_HANDLE> for Hierarchy {
    type Error = Error;

    fn try_from(handle: TPM2_HANDLE) -> Result<Self> {
        match handle {
            TPM2_RH_OWNER | ESYS_TR_RH_OWNER => Ok(Hierarchy::Owner),
            TPM2_RH_PLATFORM | ESYS_TR_RH_PLATFORM => Ok(Hierarchy::Platform),
            TPM2_RH_ENDORSEMENT | ESYS_TR_RH_ENDORSEMENT => Ok(Hierarchy::Endorsement),
            TPM2_RH_NULL | ESYS_TR_RH_NULL => Ok(Hierarchy::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Enables
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enables {
    Owner,
    Platform,
    Endorsement,
    PlatformNv,
    Null,
}

impl Enables {
    /// Get the ESYS resource handle for the enables.
    pub fn esys_rh(self) -> ESYS_TR {
        match self {
            Enables::Owner => ESYS_TR_RH_OWNER,
            Enables::Platform => ESYS_TR_RH_PLATFORM,
            Enables::Endorsement => ESYS_TR_RH_ENDORSEMENT,
            Enables::PlatformNv => ESYS_TR_RH_PLATFORM_NV,
            Enables::Null => ESYS_TR_RH_NULL,
        }
    }

    /// Get the TPM resource handle for the enables.
    pub fn rh(self) -> TPM2_RH {
        match self {
            Enables::Owner => TPM2_RH_OWNER,
            Enables::Platform => TPM2_RH_PLATFORM,
            Enables::Endorsement => TPM2_RH_ENDORSEMENT,
            Enables::PlatformNv => TPM2_RH_PLATFORM_NV,
            Enables::Null => TPM2_RH_NULL,
        }
    }
}

impl TryFrom<TPM2_HANDLE> for Enables {
    type Error = Error;

    fn try_from(handle: TPM2_HANDLE) -> Result<Self> {
        match handle {
            TPM2_RH_OWNER | ESYS_TR_RH_OWNER => Ok(Enables::Owner),
            TPM2_RH_PLATFORM | ESYS_TR_RH_PLATFORM => Ok(Enables::Platform),
            TPM2_RH_ENDORSEMENT | ESYS_TR_RH_ENDORSEMENT => Ok(Enables::Endorsement),
            TPM2_RH_PLATFORM_NV | ESYS_TR_RH_PLATFORM_NV => Ok(Enables::PlatformNv),
            TPM2_RH_NULL | ESYS_TR_RH_NULL => Ok(Enables::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// HierarchyAuth
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HierarchyAuth {
    Owner,
    Platform,
    Endorsement,
    Lockout,
}

impl HierarchyAuth {
    /// Get the ESYS resource handle for the hierarchy auth.
    pub fn esys_rh(self) -> ESYS_TR {
        match self {
            HierarchyAuth::Owner => ESYS_TR_RH_OWNER,
            HierarchyAuth::Platform => ESYS_TR_RH_PLATFORM,
            HierarchyAuth::Endorsement => ESYS_TR_RH_ENDORSEMENT,
            HierarchyAuth::Lockout => ESYS_TR_RH_LOCKOUT,
        }
    }

    /// Get the TPM resource handle for the hierarchy auth.
    pub fn rh(self) -> TPM2_RH {
        match self {
            HierarchyAuth::Owner => TPM2_RH_OWNER,
            HierarchyAuth::Platform => TPM2_RH_PLATFORM,
            HierarchyAuth::Endorsement => TPM2_RH_ENDORSEMENT,
            HierarchyAuth::Lockout => TPM2_RH_LOCKOUT,
        }
    }
}

impl TryFrom<TPM2_HANDLE> for HierarchyAuth {
    type Error = Error;

    fn try_from(handle: TPM2_HANDLE) -> Result<Self> {
        match handle {
            TPM2_RH_OWNER | ESYS_TR_RH_OWNER => Ok(HierarchyAuth::Owner),
            TPM2_RH_PLATFORM | ESYS_TR_RH_PLATFORM => Ok(HierarchyAuth::Platform),
            TPM2_RH_ENDORSEMENT | ESYS_TR_RH_ENDORSEMENT => Ok(HierarchyAuth::Endorsement),
            TPM2_RH_LOCKOUT | ESYS_TR_RH_LOCKOUT => Ok(HierarchyAuth::Lockout),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// TODO: HierarchyPolicy
//////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////////////
/// Platform
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Platform,
}

impl From<Platform> for AuthHandle {
    fn from(_: Platform) -> AuthHandle {
        AuthHandle::PlatformHandle
    }
}

impl TryFrom<AuthHandle> for Platform {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Platform> {
        match auth_handle {
            AuthHandle::PlatformHandle => Ok(Platform::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Owner
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    Owner,
    Null, // TODO: Remove null and use Option instead?
}

impl From<Owner> for TpmConstantsHandle {
    fn from(owner: Owner) -> TpmConstantsHandle {
        match owner {
            Owner::Owner => TpmConstantsHandle::Owner,
            Owner::Null => TpmConstantsHandle::Null,
        }
    }
}

impl TryFrom<TpmConstantsHandle> for Owner {
    type Error = Error;

    fn try_from(tpm_constant_handle: TpmConstantsHandle) -> Result<Owner> {
        match tpm_constant_handle {
            TpmConstantsHandle::Owner => Ok(Owner::Owner),
            TpmConstantsHandle::Null => Ok(Owner::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Endorsement
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endorsement {
    Endorsement,
    Null,
}

impl From<Endorsement> for TpmConstantsHandle {
    fn from(endorsement: Endorsement) -> TpmConstantsHandle {
        match endorsement {
            Endorsement::Endorsement => TpmConstantsHandle::Endorsement,
            Endorsement::Null => TpmConstantsHandle::Null,
        }
    }
}

impl TryFrom<TpmConstantsHandle> for Endorsement {
    type Error = Error;

    fn try_from(tpm_constants_handle: TpmConstantsHandle) -> Result<Endorsement> {
        match tpm_constants_handle {
            TpmConstantsHandle::Endorsement => Ok(Endorsement::Endorsement),
            TpmConstantsHandle::Null => Ok(Endorsement::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Provision
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provision {
    Owner,
    Platform,
}

impl From<Provision> for AuthHandle {
    fn from(provision: Provision) -> AuthHandle {
        match provision {
            Provision::Owner => AuthHandle::OwnerHandle,
            Provision::Platform => AuthHandle::PlatformHandle,
        }
    }
}

impl TryFrom<AuthHandle> for Provision {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Provision> {
        match auth_handle {
            AuthHandle::OwnerHandle => Ok(Provision::Owner),
            AuthHandle::PlatformHandle => Ok(Provision::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Clear
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Clear {
    Owner,
    Platform,
}

impl From<Clear> for AuthHandle {
    fn from(clear: Clear) -> AuthHandle {
        match clear {
            Clear::Owner => AuthHandle::OwnerHandle,
            Clear::Platform => AuthHandle::PlatformHandle,
        }
    }
}

impl TryFrom<AuthHandle> for Clear {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<Self> {
        match auth_handle {
            AuthHandle::OwnerHandle => Ok(Clear::Owner),
            AuthHandle::PlatformHandle => Ok(Clear::Platform),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// NvAuth
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvAuth {
    Platform,
    Owner,
    NvIndex(NvIndexHandle),
}

impl From<NvAuth> for AuthHandle {
    fn from(nv_auth: NvAuth) -> AuthHandle {
        match nv_auth {
            NvAuth::Platform => AuthHandle::PlatformHandle,
            NvAuth::Owner => AuthHandle::OwnerHandle,
            NvAuth::NvIndex(nv_index_handle) => nv_index_handle.into(),
        }
    }
}

impl TryFrom<AuthHandle> for NvAuth {
    type Error = Error;

    fn try_from(auth_handle: AuthHandle) -> Result<NvAuth> {
        match auth_handle {
            AuthHandle::PlatformHandle => Ok(NvAuth::Platform),
            AuthHandle::OwnerHandle => Ok(NvAuth::Owner),
            _ => Ok(NvAuth::NvIndex(NvIndexHandle::from(auth_handle))),
        }
    }
}
//////////////////////////////////////////////////////////////////////////////////
/// Lockout
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockout {
    Lockout,
}

impl From<Lockout> for TpmConstantsHandle {
    fn from(_: Lockout) -> TpmConstantsHandle {
        TpmConstantsHandle::Lockout
    }
}

impl TryFrom<TpmConstantsHandle> for Lockout {
    type Error = Error;

    fn try_from(tpm_constants_handle: TpmConstantsHandle) -> Result<Lockout> {
        match tpm_constants_handle {
            TpmConstantsHandle::Lockout => Ok(Lockout::Lockout),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// NvIndex
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvIndex {
    NvIndex(NvIndexTpmHandle),
}

impl From<NvIndexTpmHandle> for NvIndex {
    fn from(nv_index_tpm_handle: NvIndexTpmHandle) -> NvIndex {
        NvIndex::NvIndex(nv_index_tpm_handle)
    }
}

impl From<NvIndex> for NvIndexTpmHandle {
    fn from(nv_index: NvIndex) -> NvIndexTpmHandle {
        match nv_index {
            NvIndex::NvIndex(handle) => handle,
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
/// AttachedComponent
//////////////////////////////////////////////////////////////////////////////////
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachedComponent {
    AttachedComponent(AttachedComponentTpmHandle),
}

impl From<AttachedComponentTpmHandle> for AttachedComponent {
    fn from(attached_component_tpm_handle: AttachedComponentTpmHandle) -> AttachedComponent {
        AttachedComponent::AttachedComponent(attached_component_tpm_handle)
    }
}

impl From<AttachedComponent> for AttachedComponentTpmHandle {
    fn from(attached_component: AttachedComponent) -> AttachedComponentTpmHandle {
        match attached_component {
            AttachedComponent::AttachedComponent(handle) => handle,
        }
    }
}

//////////////////////////////////////////////////////////////////////////////////
// Act
//
// TODO: Figure out how to implement this. This is some kind of counter.
//////////////////////////////////////////////////////////////////////////////////
