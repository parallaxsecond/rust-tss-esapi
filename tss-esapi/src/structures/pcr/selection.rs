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
use std::iter::FromIterator;
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
    /// Creates new PcrSelection
    pub fn new(
        hashing_algorithm: HashingAlgorithm,
        size_of_select: PcrSelectSize,
        selected_pcr_slots: &[PcrSlot],
    ) -> Self {
        PcrSelection {
            hashing_algorithm,
            size_of_select,
            selected_pcrs: Self::to_internal_representation(selected_pcr_slots),
        }
    }

    /// Returns the hashing algorithm for the selection
    pub const fn hashing_algorithm(&self) -> HashingAlgorithm {
        self.hashing_algorithm
    }

    /// Returns 'Size of Select'
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the selection but rather how many
    /// octets that are needed to hold the bit field
    /// that indicate what slots that are selected.
    pub const fn size_of_select(&self) -> PcrSelectSize {
        self.size_of_select
    }

    /// Returns the selected pcrs.
    pub fn selected(&self) -> Vec<PcrSlot> {
        self.selected_pcrs.iter().collect()
    }

    /// Returns true if the specified [PcrSlot] is selected in
    /// the [PcrSelection].
    pub fn is_selected(&self, pcr_slot: PcrSlot) -> bool {
        self.selected_pcrs.contains(pcr_slot)
    }

    /// Removes the specified [PcrSlot]s from the selected pcrs.
    ///
    /// # Error
    /// If one of the specified pcr slots does not exist in the selected pcrs.
    pub fn deselect_exact(&mut self, pcr_slot: PcrSlot) -> Result<()> {
        self.remove_exact(pcr_slot.into())
    }

    /// Removes the specified [PcrSlot]s from the selected pcrs.
    pub fn deselect(&mut self, pcr_slot: PcrSlot) {
        self.remove(pcr_slot.into())
    }

    /// Merges another [PcrSelection] into this one.
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
            error!("Mismatched hashing algorithm ");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        // Check that size of select match.
        if self.size_of_select != other.size_of_select {
            error!("Mismatched size of select");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        self.remove_exact(other.selected_pcrs)
    }

    /// Indicates whether the pcr selection is empty.
    pub fn is_empty(&self) -> bool {
        self.selected_pcrs.is_empty()
    }

    /// Private function for converting a slize of pcr slots to
    /// internal representation.
    fn to_internal_representation(pcr_slots: &[PcrSlot]) -> BitFlags<PcrSlot> {
        BitFlags::<PcrSlot>::from_iter(pcr_slots.iter().copied())
    }

    /// Removes bitflags from selected pcrs
    ///
    /// # Error
    /// Returns an error if the any of the bit flags does
    /// not exist in the selected pcrs.
    fn remove_exact(&mut self, bit_flags: BitFlags<PcrSlot>) -> Result<()> {
        if self.selected_pcrs.contains(bit_flags) {
            self.remove(bit_flags);
            Ok(())
        } else {
            error!("Failed to remove item, it does not exist");
            Err(Error::local_error(WrapperErrorKind::InvalidParam))
        }
    }

    /// Removes bitflags from selected pcrs
    fn remove(&mut self, bit_flags: BitFlags<PcrSlot>) {
        self.selected_pcrs.remove(bit_flags)
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
