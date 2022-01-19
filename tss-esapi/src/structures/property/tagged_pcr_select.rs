// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    constants::PcrPropertyTag,
    structures::{PcrSelectSize, PcrSlot},
    tss2_esys::{TPM2_PCR_SELECT_MAX, TPMS_TAGGED_PCR_SELECT},
    Error, Result, WrapperErrorKind,
};
use enumflags2::BitFlags;
use log::error;
use std::convert::TryFrom;
use std::iter::FromIterator;

/// Type that holds information regarding
/// what PCR slots that are associated with
/// a specific pcr property tag.
///
/// This corresponds to the TPMS_TAGGED_PCR_SELECT.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct TaggedPcrSelect {
    pcr_property_tag: PcrPropertyTag,
    size_of_select: PcrSelectSize,
    selected_pcrs: BitFlags<PcrSlot>,
}

impl TaggedPcrSelect {
    /// Creates a new TaggedPcrSelect
    pub fn new(
        pcr_property_tag: PcrPropertyTag,
        size_of_select: PcrSelectSize,
        selected_pcr_slots: &[PcrSlot],
    ) -> Self {
        TaggedPcrSelect {
            pcr_property_tag,
            size_of_select,
            selected_pcrs: Self::to_internal_representation(selected_pcr_slots),
        }
    }

    /// Returns the property identifier
    pub const fn pcr_property_tag(&self) -> PcrPropertyTag {
        self.pcr_property_tag
    }

    /// Returns the size of the select
    ///
    /// NB! This is not the same as how many [PcrSlot]
    /// there are in the select, but rather how many
    /// octets are needed to hold the bit field which
    /// indicates what slots have the [PcrPropertyTag]
    /// property.
    pub const fn size_of_select(&self) -> PcrSelectSize {
        self.size_of_select
    }

    /// Returns the pcr slots that has the property
    /// indicated by the pcr property tag.
    pub fn selected_pcrs(&self) -> Vec<PcrSlot> {
        self.selected_pcrs.iter().collect()
    }

    /// Private function for converting a slize of pcr slots to
    /// internal representation.
    fn to_internal_representation(pcr_slots: &[PcrSlot]) -> BitFlags<PcrSlot> {
        BitFlags::<PcrSlot>::from_iter(pcr_slots.iter().copied())
    }
}

impl TryFrom<TPMS_TAGGED_PCR_SELECT> for TaggedPcrSelect {
    type Error = Error;
    fn try_from(tpms_tagged_pcr_select: TPMS_TAGGED_PCR_SELECT) -> Result<Self> {
        // Parse the tag.
        let pcr_property_tag = PcrPropertyTag::try_from(tpms_tagged_pcr_select.tag)?;

        // Parse the sizeofSelect into a SelectSize.
        let size_of_select = PcrSelectSize::try_from(tpms_tagged_pcr_select.sizeofSelect)?;

        // Select only the octets indicated by sizeofSelect
        let mut selected_octets = [0u8; TPM2_PCR_SELECT_MAX as usize];
        let number_of_selected_octets: usize = size_of_select.into();
        selected_octets[..number_of_selected_octets]
            .copy_from_slice(&tpms_tagged_pcr_select.pcrSelect[..number_of_selected_octets]);

        // Parse selected pcrs into BitFlags
        let selected_pcrs = BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(selected_octets))
            .map_err(|e| {
                error!("Error parsing pcrSelect to a BitFlags<PcrSlot>: {}.", e);
                Error::local_error(WrapperErrorKind::UnsupportedParam)
            })?;

        Ok(TaggedPcrSelect {
            pcr_property_tag,
            size_of_select,
            selected_pcrs,
        })
    }
}

impl From<TaggedPcrSelect> for TPMS_TAGGED_PCR_SELECT {
    fn from(tagged_pcr_select: TaggedPcrSelect) -> Self {
        TPMS_TAGGED_PCR_SELECT {
            tag: tagged_pcr_select.pcr_property_tag.into(),
            sizeofSelect: tagged_pcr_select.size_of_select.into(),
            pcrSelect: tagged_pcr_select.selected_pcrs.bits().to_le_bytes(),
        }
    }
}
