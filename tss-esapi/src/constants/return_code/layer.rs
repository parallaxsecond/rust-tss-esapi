// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TSS2_ESYS_RC_LAYER, TSS2_FEATURE_RC_LAYER, TSS2_MU_RC_LAYER, TSS2_RESMGR_RC_LAYER,
        TSS2_RESMGR_TPM_RC_LAYER, TSS2_SYS_RC_LAYER, TSS2_TCTI_RC_LAYER, TSS2_TPM_RC_LAYER,
    },
    Error, Result, WrapperErrorKind,
};

use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;

/// Enum representing the TSS layer of a
/// return code.
#[derive(FromPrimitive, ToPrimitive, Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ReturnCodeLayer {
    Tpm = u32::to_le_bytes(TSS2_TPM_RC_LAYER)[2],
    Feature = u32::to_le_bytes(TSS2_FEATURE_RC_LAYER)[2],
    Esys = u32::to_le_bytes(TSS2_ESYS_RC_LAYER)[2],
    Sys = u32::to_le_bytes(TSS2_SYS_RC_LAYER)[2],
    Mu = u32::to_le_bytes(TSS2_MU_RC_LAYER)[2],
    Tcti = u32::to_le_bytes(TSS2_TCTI_RC_LAYER)[2],
    ResMgr = u32::to_le_bytes(TSS2_RESMGR_RC_LAYER)[2],
    ResMgrTpm = u32::to_le_bytes(TSS2_RESMGR_TPM_RC_LAYER)[2],
}

impl TryFrom<u8> for ReturnCodeLayer {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        ReturnCodeLayer::from_u8(value).ok_or_else(|| {
            error!("{:#02X} is not valid ReturnCodeLayer", value);
            Error::local_error(WrapperErrorKind::InvalidParam)
        })
    }
}

impl From<ReturnCodeLayer> for u8 {
    fn from(return_code_layer: ReturnCodeLayer) -> u8 {
        // The values are well defined so unwrap cannot panic.
        return_code_layer.to_u8().unwrap()
    }
}
