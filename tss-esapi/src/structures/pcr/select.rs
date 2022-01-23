// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    structures::{PcrSelectSize, PcrSlot},
    tss2_esys::{TPM2_PCR_SELECT_MAX, TPMS_PCR_SELECT},
    Error, Result, WrapperErrorKind,
};

use enumflags2::BitFlags;
use log::error;

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
            selected_pcrs: pcr_slots.iter().copied().collect(),
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
        let size_of_select = PcrSelectSize::try_from(tss_pcr_select.sizeofSelect)?;

        // Select only the octets indicated by sizeofSelect
        let mut selected_octets = [0u8; TPM2_PCR_SELECT_MAX as usize];
        let number_of_selected_octets: usize = size_of_select.as_usize();
        selected_octets[..number_of_selected_octets]
            .copy_from_slice(&tss_pcr_select.pcrSelect[..number_of_selected_octets]);

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
            sizeofSelect: pcr_select.size_of_select.as_u8(),
            pcrSelect: pcr_select.selected_pcrs.bits().to_le_bytes(),
        }
    }
}
