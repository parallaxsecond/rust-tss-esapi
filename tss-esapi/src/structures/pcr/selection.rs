// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::interface_types::algorithm::HashingAlgorithm;
use crate::structures::{PcrSelectSize, PcrSlot};
use crate::tss2_esys::TPMS_PCR_SELECTION;
use crate::{Error, Result, WrapperErrorKind};
use enumflags2::BitFlags;
use log::error;
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{From, TryFrom};
/// This module contains the PcrSelection struct.
/// The TSS counterpart of this struct is the
/// TPMS_PCR_SELECTION.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    hashing_algorithm: HashingAlgorithm,
    size_of_select: PcrSelectSize,
    selected_pcrs: BitFlags<PcrSlot>,
}

impl PcrSelection {
    pub fn new(
        hashing_algorithm: HashingAlgorithm,
        size_of_select: PcrSelectSize,
        selected_pcr_slots: &[PcrSlot],
    ) -> Self {
        PcrSelection {
            hashing_algorithm,
            size_of_select,
            selected_pcrs: selected_pcr_slots.iter().cloned().collect(),
        }
    }

    pub fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    pub fn selected_pcrs(&self) -> &BitFlags<PcrSlot> {
        &self.selected_pcrs
    }

    pub fn merge(&mut self, other: &Self) -> Result<()> {
        // Check that the hashing algorithm match
        if self.hashing_algorithm != other.hashing_algorithm {
            error!("Error: Found inconsistencies in the hashing algorithm");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        // Check that size of select match.
        if self.size_of_select != other.size_of_select {
            error!("Error: Found inconsistencies in the size of select");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        self.selected_pcrs |= other.selected_pcrs;
        Ok(())
    }

    /// Removes the selected values in `other` from `self`.
    ///
    /// # Constraints
    /// * Cannot be called with `other` that has a hashing_algorithm
    ///   that is different from the one in `self`.
    /// * Cannot be called with `other` that has a size_of_select
    ///   that is different from the one in `self`.
    pub fn subtract(&mut self, other: &Self) -> Result<()> {
        // Check that the hashing algorithm match
        if self.hashing_algorithm != other.hashing_algorithm {
            error!("Error: Found inconsistencies in the hashing algorithm");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        // Check that size of select match.
        if self.size_of_select != other.size_of_select {
            error!("Error: Found inconsistencies in the size of select");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        // Check if the value in other is contained in current select
        if !self.selected_pcrs.contains(other.selected_pcrs) {
            error!("Error: Trying to remove item that did not exist");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        self.selected_pcrs.remove(other.selected_pcrs);
        Ok(())
    }

    /// Indicates wether the pcr selection is empty.
    pub fn is_empty(&self) -> bool {
        self.selected_pcrs.is_empty()
    }
}

impl TryFrom<TPMS_PCR_SELECTION> for PcrSelection {
    type Error = Error;
    fn try_from(tss_pcr_selection: TPMS_PCR_SELECTION) -> Result<Self> {
        Ok(PcrSelection {
            // Parse hashing algorithm.
            hashing_algorithm: HashingAlgorithm::try_from(tss_pcr_selection.hash).map_err(|e| {
                error!("Error converting hash to a HashingAlgorithm: {}", e);
                Error::local_error(WrapperErrorKind::InvalidParam)
            })?,
            // Parse the sizeofSelect into a SelectSize.
            size_of_select: PcrSelectSize::from_u8(tss_pcr_selection.sizeofSelect).ok_or_else(
                || {
                    error!(
                        "Error converting sizeofSelect to a SelectSize: Invalid value {}",
                        tss_pcr_selection.sizeofSelect
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                },
            )?,
            // Parse selected pcrs into BitFlags
            selected_pcrs: BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(
                tss_pcr_selection.pcrSelect,
            ))
            .map_err(|e| {
                error!("Error parsing pcrSelect to a BitFlags<PcrSlot>: {}", e);
                Error::local_error(WrapperErrorKind::UnsupportedParam)
            })?,
        })
    }
}

impl From<PcrSelection> for TPMS_PCR_SELECTION {
    fn from(pcr_selection: PcrSelection) -> Self {
        TPMS_PCR_SELECTION {
            hash: pcr_selection.hashing_algorithm.into(),
            sizeofSelect: pcr_selection.size_of_select.to_u8().unwrap(),
            pcrSelect: pcr_selection.selected_pcrs.bits().to_le_bytes(),
        }
    }
}
