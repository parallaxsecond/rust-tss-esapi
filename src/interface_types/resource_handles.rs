// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    handles::{
        AttachedComponentTpmHandle, AuthHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle,
        PermanentTpmHandle, TpmConstantsHandle, TpmHandle,
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

impl From<Hierarchy> for ObjectHandle {
    fn from(hierarchy: Hierarchy) -> ObjectHandle {
        match hierarchy {
            Hierarchy::Owner => ObjectHandle::OwnerHandle,
            Hierarchy::Platform => ObjectHandle::PlatformHandle,
            Hierarchy::Endorsement => ObjectHandle::EndorsementHandle,
            Hierarchy::Null => ObjectHandle::NullHandle,
        }
    }
}

impl From<Hierarchy> for TpmHandle {
    fn from(hierarchy: Hierarchy) -> TpmHandle {
        match hierarchy {
            Hierarchy::Owner => TpmHandle::Permanent(PermanentTpmHandle::OwnerHandle),
            Hierarchy::Platform => TpmHandle::Permanent(PermanentTpmHandle::PlatformHandle),
            Hierarchy::Endorsement => TpmHandle::Permanent(PermanentTpmHandle::EndorsementHandle),
            Hierarchy::Null => TpmHandle::Permanent(PermanentTpmHandle::NullHandle),
        }
    }
}

impl TryFrom<ObjectHandle> for Hierarchy {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Hierarchy> {
        match object_handle {
            ObjectHandle::OwnerHandle => Ok(Hierarchy::Owner),
            ObjectHandle::PlatformHandle => Ok(Hierarchy::Platform),
            ObjectHandle::EndorsementHandle => Ok(Hierarchy::Endorsement),
            ObjectHandle::NullHandle => Ok(Hierarchy::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for Hierarchy {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Hierarchy> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::OwnerHandle => Ok(Hierarchy::Owner),
                PermanentTpmHandle::PlatformHandle => Ok(Hierarchy::Platform),
                PermanentTpmHandle::EndorsementHandle => Ok(Hierarchy::Endorsement),
                PermanentTpmHandle::NullHandle => Ok(Hierarchy::Null),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
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

impl From<Enables> for ObjectHandle {
    fn from(enables: Enables) -> ObjectHandle {
        match enables {
            Enables::Owner => ObjectHandle::OwnerHandle,
            Enables::Platform => ObjectHandle::PlatformHandle,
            Enables::Endorsement => ObjectHandle::EndorsementHandle,
            Enables::PlatformNv => ObjectHandle::PlatformNvHandle,
            Enables::Null => ObjectHandle::NullHandle,
        }
    }
}

impl From<Enables> for TpmHandle {
    fn from(enables: Enables) -> TpmHandle {
        match enables {
            Enables::Owner => TpmHandle::Permanent(PermanentTpmHandle::OwnerHandle),
            Enables::Platform => TpmHandle::Permanent(PermanentTpmHandle::PlatformHandle),
            Enables::Endorsement => TpmHandle::Permanent(PermanentTpmHandle::EndorsementHandle),
            Enables::PlatformNv => TpmHandle::Permanent(PermanentTpmHandle::PlatformNvHandle),
            Enables::Null => TpmHandle::Permanent(PermanentTpmHandle::NullHandle),
        }
    }
}

impl TryFrom<ObjectHandle> for Enables {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<Enables> {
        match object_handle {
            ObjectHandle::OwnerHandle => Ok(Enables::Owner),
            ObjectHandle::PlatformHandle => Ok(Enables::Platform),
            ObjectHandle::EndorsementHandle => Ok(Enables::Endorsement),
            ObjectHandle::PlatformNvHandle => Ok(Enables::PlatformNv),
            ObjectHandle::NullHandle => Ok(Enables::Null),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for Enables {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<Enables> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::OwnerHandle => Ok(Enables::Owner),
                PermanentTpmHandle::PlatformHandle => Ok(Enables::Platform),
                PermanentTpmHandle::EndorsementHandle => Ok(Enables::Endorsement),
                PermanentTpmHandle::PlatformNvHandle => Ok(Enables::PlatformNv),
                PermanentTpmHandle::NullHandle => Ok(Enables::Null),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
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

impl From<HierarchyAuth> for ObjectHandle {
    fn from(hierarchy_auth: HierarchyAuth) -> ObjectHandle {
        match hierarchy_auth {
            HierarchyAuth::Owner => ObjectHandle::OwnerHandle,
            HierarchyAuth::Platform => ObjectHandle::PlatformHandle,
            HierarchyAuth::Endorsement => ObjectHandle::EndorsementHandle,
            HierarchyAuth::Lockout => ObjectHandle::LockoutHandle,
        }
    }
}

impl From<HierarchyAuth> for TpmHandle {
    fn from(hierarchy_auth: HierarchyAuth) -> TpmHandle {
        match hierarchy_auth {
            HierarchyAuth::Owner => TpmHandle::Permanent(PermanentTpmHandle::OwnerHandle),
            HierarchyAuth::Platform => TpmHandle::Permanent(PermanentTpmHandle::PlatformHandle),
            HierarchyAuth::Endorsement => {
                TpmHandle::Permanent(PermanentTpmHandle::EndorsementHandle)
            }
            HierarchyAuth::Lockout => TpmHandle::Permanent(PermanentTpmHandle::LockoutHandle),
        }
    }
}

impl TryFrom<ObjectHandle> for HierarchyAuth {
    type Error = Error;

    fn try_from(object_handle: ObjectHandle) -> Result<HierarchyAuth> {
        match object_handle {
            ObjectHandle::OwnerHandle => Ok(HierarchyAuth::Owner),
            ObjectHandle::PlatformHandle => Ok(HierarchyAuth::Platform),
            ObjectHandle::EndorsementHandle => Ok(HierarchyAuth::Endorsement),
            ObjectHandle::LockoutHandle => Ok(HierarchyAuth::Lockout),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}

impl TryFrom<TpmHandle> for HierarchyAuth {
    type Error = Error;

    fn try_from(tpm_handle: TpmHandle) -> Result<HierarchyAuth> {
        match tpm_handle {
            TpmHandle::Permanent(permanent_handle) => match permanent_handle {
                PermanentTpmHandle::OwnerHandle => Ok(HierarchyAuth::Owner),
                PermanentTpmHandle::PlatformHandle => Ok(HierarchyAuth::Platform),
                PermanentTpmHandle::EndorsementHandle => Ok(HierarchyAuth::Endorsement),
                PermanentTpmHandle::LockoutHandle => Ok(HierarchyAuth::Lockout),
                _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            },
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
// Act (authenticated timers)
//
// TODO: Figure out how to implement this. This is some kind of counter.
//////////////////////////////////////////////////////////////////////////////////
