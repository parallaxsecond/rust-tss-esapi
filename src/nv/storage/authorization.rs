// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    tss2_esys::{ESYS_TR, ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM},
    utils::Hierarchy,
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{From, TryFrom};
/// Enum representing the only type of authorizations
/// allowed.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum NvAuthorization {
    Owner,
    Platform,
}

impl From<NvAuthorization> for Hierarchy {
    fn from(nv_auhtorization: NvAuthorization) -> Hierarchy {
        match nv_auhtorization {
            NvAuthorization::Owner => Hierarchy::Owner,
            NvAuthorization::Platform => Hierarchy::Platform,
        }
    }
}

impl TryFrom<Hierarchy> for NvAuthorization {
    type Error = Error;

    fn try_from(hierarchy: Hierarchy) -> Result<NvAuthorization> {
        match hierarchy {
            Hierarchy::Owner => Ok(NvAuthorization::Owner),
            Hierarchy::Platform => Ok(NvAuthorization::Platform),
            _ => {
                error!("Error: Found invalid value when trying to convert Hierarchy to NV Authroization.");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

impl From<NvAuthorization> for ESYS_TR {
    fn from(nv_auhtorization: NvAuthorization) -> ESYS_TR {
        match nv_auhtorization {
            NvAuthorization::Owner => ESYS_TR_RH_OWNER,
            NvAuthorization::Platform => ESYS_TR_RH_PLATFORM,
        }
    }
}

impl TryFrom<ESYS_TR> for NvAuthorization {
    type Error = Error;

    fn try_from(esys_tr: ESYS_TR) -> Result<NvAuthorization> {
        match esys_tr {
            ESYS_TR_RH_OWNER => Ok(NvAuthorization::Owner),
            ESYS_TR_RH_PLATFORM => Ok(NvAuthorization::Platform),
            _ => {
                error!("Error: Found invalid value when trying parse NV Authroization");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}
