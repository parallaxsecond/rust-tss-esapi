// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::{
        TPM2_HT_NV_INDEX, TPM2_NT_BITS, TPM2_NT_COUNTER, TPM2_NT_EXTEND, TPM2_NT_ORDINARY,
        TPM2_NT_PIN_FAIL, TPM2_NT_PIN_PASS,
    },
    tss2_esys::{ESYS_TR, TPM2_NT, TPMA_NV, TPMI_RH_NV_INDEX},
    Error, Result, WrapperErrorKind,
};

use bitfield::bitfield;
use log::error;
use std::convert::{From, TryFrom};

///
/// Struct representing the NvIndex.
///
/// The NvIndex is a TPM handle and it must
/// have a most significant octet that is
/// equal to TPM_HT_NV_INDEX.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NvIndex {
    value: u32,
}

impl NvIndex {
    /// Creates index using the specified value.
    ///
    /// # Errors
    /// * If `value` does not have a most significant octet
    ///   that is equal to TPM_HT_NV_INDEX an `InvalidParam`
    ///   error is returned.
    pub fn create_from_value(value: u32) -> Result<Self> {
        let most_significant_octet = value.to_be_bytes()[0];
        if most_significant_octet != TPM2_HT_NV_INDEX {
            error!(
                "Error: Value has invalid most significant octet(={})",
                most_significant_octet
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        Ok(NvIndex { value })
    }

    /// Creates an index from an offset of the
    /// TPM_HT_NV_INDEX.
    ///
    /// # Errors
    /// * If the offset is greater 16 777 215 (i.e. most
    ///   significant octet is not 0) an `InvalidParam`
    ///   error is returned.
    pub fn create_from_offset(offset: u32) -> Result<Self> {
        let mut nv_index_be_bytes = offset.to_be_bytes();
        // Check that ha value is not to big.
        let most_significant_octet = nv_index_be_bytes[0];
        if most_significant_octet != 0 {
            error!("Error: Offset is to big (> 16777215)");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        // Add the correct most significant octet for Nv Index.
        nv_index_be_bytes[0] = TPM2_HT_NV_INDEX;
        Ok(NvIndex {
            value: u32::from_be_bytes(nv_index_be_bytes),
        })
    }
}

impl TryFrom<TPMI_RH_NV_INDEX> for NvIndex {
    type Error = Error;
    fn try_from(tss_nv_index: TPMI_RH_NV_INDEX) -> Result<NvIndex> {
        NvIndex::create_from_value(tss_nv_index)
    }
}

impl From<NvIndex> for TPMI_RH_NV_INDEX {
    fn from(nv_index: NvIndex) -> TPMI_RH_NV_INDEX {
        nv_index.value
    }
}

/// Represents the esys handled used for referencing
/// the nv index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NvIndexHandle {
    value: u32,
}

impl From<ESYS_TR> for NvIndexHandle {
    fn from(esys_resource_handle: ESYS_TR) -> NvIndexHandle {
        NvIndexHandle {
            value: esys_resource_handle,
        }
    }
}

impl From<NvIndexHandle> for ESYS_TR {
    fn from(nv_index_handle: NvIndexHandle) -> ESYS_TR {
        nv_index_handle.value
    }
}

/// Enum with values representing the NV index type.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NvIndexType {
    Ordinary,
    Counter,
    Bits,
    Extend,
    PinFail,
    PinPass,
}

impl From<NvIndexType> for TPM2_NT {
    fn from(nv_index_type: NvIndexType) -> TPM2_NT {
        match nv_index_type {
            NvIndexType::Ordinary => TPM2_NT_ORDINARY,
            NvIndexType::Counter => TPM2_NT_COUNTER,
            NvIndexType::Bits => TPM2_NT_BITS,
            NvIndexType::Extend => TPM2_NT_EXTEND,
            NvIndexType::PinFail => TPM2_NT_PIN_FAIL,
            NvIndexType::PinPass => TPM2_NT_PIN_PASS,
        }
    }
}

impl TryFrom<TPM2_NT> for NvIndexType {
    type Error = Error;
    fn try_from(tss_nv_index_type: TPM2_NT) -> Result<NvIndexType> {
        match tss_nv_index_type {
            TPM2_NT_ORDINARY => Ok(NvIndexType::Ordinary),
            TPM2_NT_COUNTER => Ok(NvIndexType::Counter),
            TPM2_NT_BITS => Ok(NvIndexType::Bits),
            TPM2_NT_EXTEND => Ok(NvIndexType::Extend),
            TPM2_NT_PIN_FAIL => Ok(NvIndexType::PinFail),
            TPM2_NT_PIN_PASS => Ok(NvIndexType::PinPass),
            _ => {
                error!("Error: Found invalid value when trying to parse Nv Index Type.");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }
}

bitfield! {
    /// Bitfield representing the nv index attributes.
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub struct NvIndexAttributes(TPMA_NV);
    impl Debug;
    // NV Index Attributes
    pub pp_write, set_pp_write: 0;
    pub owner_write, set_owner_write: 1;
    pub auth_write, set_auth_write: 2;
    pub policy_write, set_policy_write: 3;
    TPM2_NT, tss_index_type, _: 7, 4; // private getter
    pub TPM2_NT, from into NvIndexType, _, set_index_type: 7, 4;
    // Reserved 9,8
    pub policy_delete, set_policy_delete: 10;
    pub write_locked, set_write_locked: 11;
    pub write_all, set_write_all: 12;
    pub write_define, set_write_define: 13;
    pub write_stclear, set_write_stclear: 14;
    pub global_lock, set_global_lock: 15;
    pub pp_read, set_pp_read: 16;
    pub owner_read, set_owner_read: 17;
    pub auth_read, set_auth_read: 18;
    pub policy_read, set_policy_read: 19;
    // Reserved 24, 20
    pub no_da, set_no_da: 25;
    pub orderly, set_orderly: 26;
    pub clear_stclear, set_clear_stclear: 27;
    pub read_locked, set_read_locked: 28;
    pub written, set_written: 29;
    pub platform_create, set_platform_create: 30;
    pub read_stclear, set_read_stclear: 31;
}

impl NvIndexAttributes {
    pub fn index_type(&self) -> Result<NvIndexType> {
        NvIndexType::try_from(self.tss_index_type())
    }
}

impl From<TPMA_NV> for NvIndexAttributes {
    fn from(tss_nv_index_atttributes: TPMA_NV) -> NvIndexAttributes {
        NvIndexAttributes(tss_nv_index_atttributes)
    }
}

impl From<NvIndexAttributes> for TPMA_NV {
    fn from(nv_index_atttributes: NvIndexAttributes) -> TPMA_NV {
        nv_index_atttributes.0
    }
}
