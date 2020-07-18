// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::TPMS_PCR_SELECT;
use crate::{Error, Result, WrapperErrorKind};
use enumflags2::BitFlags;
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{From, TryFrom};
/// This module contains necessary representations
/// of the items belonging to the TPMS_PCR_SELECT
/// structure.
///
/// The minimum number of octets allowed in a TPMS_PCR_SELECT.sizeOfSelect
/// is not determined by the number of PCR implemented but by the
/// number of PCR required by the platform-specific
/// specification with which the TPM is compliant or by the implementer if
/// not adhering to a platform-specific specification.

/// Enum with the bit flag for each PCR slot.
#[derive(BitFlags, Hash, Debug, Eq, PartialEq, Ord, PartialOrd, Clone, Copy)]
#[repr(u32)]
pub enum PcrSlot {
    Slot0 = 0x0000_0001,
    Slot1 = 0x0000_0002,
    Slot2 = 0x0000_0004,
    Slot3 = 0x0000_0008,
    Slot4 = 0x0000_0010,
    Slot5 = 0x0000_0020,
    Slot6 = 0x0000_0040,
    Slot7 = 0x0000_0080,
    Slot8 = 0x0000_0100,
    Slot9 = 0x0000_0200,
    Slot10 = 0x0000_0400,
    Slot11 = 0x0000_0800,
    Slot12 = 0x0000_1000,
    Slot13 = 0x0000_2000,
    Slot14 = 0x0000_4000,
    Slot15 = 0x0000_8000,
    Slot16 = 0x0001_0000,
    Slot17 = 0x0002_0000,
    Slot18 = 0x0004_0000,
    Slot19 = 0x0008_0000,
    Slot20 = 0x0010_0000,
    Slot21 = 0x0020_0000,
    Slot22 = 0x0040_0000,
    Slot23 = 0x0080_0000,
}

/// Enum with the possible values for sizeofSelect.
#[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum PcrSelectSize {
    OneByte = 1,
    TwoBytes = 2,
    ThreeBytes = 3,
    FourBytes = 4,
}

/// The default for PcrSelectSize is three bytes.
/// A value for the sizeofSelect that works
/// on most platforms.
impl Default for PcrSelectSize {
    fn default() -> PcrSelectSize {
        PcrSelectSize::ThreeBytes
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PcrSelect {
    size_of_select: PcrSelectSize,
    selected_pcrs: BitFlags<PcrSlot>,
}

impl PcrSelect {
    pub fn new(size_of_select: PcrSelectSize, pcr_slots: &[PcrSlot]) -> Self {
        PcrSelect {
            size_of_select,
            selected_pcrs: pcr_slots.iter().cloned().collect(),
        }
    }
}

impl TryFrom<TPMS_PCR_SELECT> for PcrSelect {
    type Error = Error;
    fn try_from(tss_pcr_select: TPMS_PCR_SELECT) -> Result<Self> {
        Ok(PcrSelect {
            // Parse the sizeofSelect into a SelectSize.
            size_of_select: PcrSelectSize::from_u8(tss_pcr_select.sizeofSelect).ok_or_else(
                || {
                    error!(
                        "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                        tss_pcr_select.sizeofSelect
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                },
            )?,
            // Parse selected pcrs into BitFlags
            selected_pcrs: BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(
                tss_pcr_select.pcrSelect,
            ))
            .map_err(|e| {
                error!("Error parsing pcrSelect to a BitFlags<PcrSlot>: {}.", e);
                Error::local_error(WrapperErrorKind::UnsupportedParam)
            })?,
        })
    }
}

impl From<PcrSelect> for TPMS_PCR_SELECT {
    fn from(pcr_select: PcrSelect) -> Self {
        TPMS_PCR_SELECT {
            sizeofSelect: pcr_select.size_of_select.to_u8().unwrap(),
            pcrSelect: pcr_select.selected_pcrs.bits().to_le_bytes(),
        }
    }
}
