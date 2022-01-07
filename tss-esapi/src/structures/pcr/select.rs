// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::PcrSlot,
    tss2_esys::{TPM2_PCR_SELECT_MAX, TPMS_PCR_SELECT},
    Error, Result, WrapperErrorKind,
};

use enumflags2::BitFlags;
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::TryFrom;
/// This module contains necessary representations
/// of the items belonging to the TPMS_PCR_SELECT
/// structure.
///
/// The minimum number of octets allowed in a TPMS_PCR_SELECT.sizeOfSelect
/// is not determined by the number of PCR implemented but by the
/// number of PCR required by the platform-specific
/// specification with which the TPM is compliant or by the implementer if
/// not adhering to a platform-specific specification.

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
    /// Creates a new PcrSelect
    pub fn new(size_of_select: PcrSelectSize, pcr_slots: &[PcrSlot]) -> Self {
        PcrSelect {
            size_of_select,
            selected_pcrs: pcr_slots.iter().cloned().collect(),
        }
    }

    /// Returns the size of the select.
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the select but rather how many
    /// octets that are needed to hold the bit field
    /// that indicate what slots that are selected.
    pub fn size_of_select(&self) -> PcrSelectSize {
        self.size_of_select
    }

    /// Returns the selected PCRs in the select.
    pub fn selected_pcrs(&self) -> Vec<PcrSlot> {
        self.selected_pcrs.iter().collect()
    }
}

impl TryFrom<TPMS_PCR_SELECT> for PcrSelect {
    type Error = Error;
    fn try_from(tss_pcr_select: TPMS_PCR_SELECT) -> Result<Self> {
        // Parse the sizeofSelect into a SelectSize.
        let size_of_select =
            PcrSelectSize::from_u8(tss_pcr_select.sizeofSelect).ok_or_else(|| {
                error!(
                    "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                    tss_pcr_select.sizeofSelect
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?;

        // Select only the octets indicated by sizeofSelect
        let mut selected_octets = [0u8; TPM2_PCR_SELECT_MAX as usize];
        selected_octets[..tss_pcr_select.sizeofSelect as usize]
            .copy_from_slice(&tss_pcr_select.pcrSelect[..tss_pcr_select.sizeofSelect as usize]);

        // Parse selected pcrs into BitFlags
        let selected_pcrs = BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(selected_octets))
            .map_err(|e| {
                error!("Error parsing pcrSelect to a BitFlags<PcrSlot>: {}.", e);
                Error::local_error(WrapperErrorKind::UnsupportedParam)
            })?;

        Ok(PcrSelect {
            size_of_select,
            selected_pcrs,
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
