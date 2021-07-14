// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::interface_types::algorithm::HashingAlgorithm;
use crate::structures::{PcrSelectSize, PcrSelection, PcrSlot};
use crate::tss2_esys::TPML_PCR_SELECTION;
use crate::{Error, Result, WrapperErrorKind};
use log::error;
use std::collections::HashMap;
use std::convert::TryFrom;
/// A struct representing a pcr selection list. This
/// corresponds to the TSS TPML_PCR_SELECTION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelectionList {
    items: Vec<PcrSelection>,
}

impl PcrSelectionList {
    pub const MAX_SIZE: usize = 16;
    /// Function for retrieiving the number of banks in the selection
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true if the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Gets the selections
    pub fn get_selections(&self) -> &[PcrSelection] {
        &self.items
    }

    /// Function for retrieving the PcrSelectionList from Option<PcrSelectionList>
    ///
    /// This returns an empty list if None is passed
    pub fn list_from_option(pcr_list: Option<PcrSelectionList>) -> PcrSelectionList {
        pcr_list.unwrap_or_else(|| PcrSelectionListBuilder::new().build())
    }
}

impl From<PcrSelectionList> for TPML_PCR_SELECTION {
    fn from(pcr_selections: PcrSelectionList) -> TPML_PCR_SELECTION {
        let mut tss_pcr_selection_list: TPML_PCR_SELECTION = Default::default();
        for pcr_selection in pcr_selections.items {
            tss_pcr_selection_list.pcrSelections[tss_pcr_selection_list.count as usize] =
                pcr_selection.into();
            tss_pcr_selection_list.count += 1;
        }
        tss_pcr_selection_list
    }
}

impl TryFrom<TPML_PCR_SELECTION> for PcrSelectionList {
    type Error = Error;
    fn try_from(tpml_pcr_selection: TPML_PCR_SELECTION) -> Result<PcrSelectionList> {
        // let mut ret: PcrSelectionList = Default::default();

        let size = tpml_pcr_selection.count as usize;

        if size > PcrSelectionList::MAX_SIZE {
            error!(
                "Invalid size value in TPML_PCR_SELECTION (> {})",
                PcrSelectionList::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let mut items = Vec::<PcrSelection>::with_capacity(size);
        // Loop over available selections
        for tpms_pcr_selection in tpml_pcr_selection.pcrSelections[..size].iter() {
            // Parse pcr selection.
            let parsed_pcr_selection = PcrSelection::try_from(*tpms_pcr_selection)?;
            items.push(parsed_pcr_selection);
        }
        Ok(PcrSelectionList { items })
    }
}

/// A builder for the PcrSelectionList struct.
#[derive(Debug, Default)]
pub struct PcrSelectionListBuilder {
    size_of_select: Option<PcrSelectSize>,
    items: HashMap<HashingAlgorithm, Vec<PcrSlot>>,
}

impl PcrSelectionListBuilder {
    pub fn new() -> Self {
        PcrSelectionListBuilder {
            size_of_select: None,
            items: Default::default(),
        }
    }

    /// Set the size of the pcr selection(sizeofSelect)
    ///
    /// # Arguments
    /// size_of_select -- The size that will be used for all selections(sizeofSelect).
    pub fn with_size_of_select(mut self, size_of_select: PcrSelectSize) -> Self {
        self.size_of_select = Some(size_of_select);
        self
    }

    /// Adds a selection associated with a specific HashingAlgorithm.
    ///
    /// This function will not overwrite the values already associated
    /// with a specific HashingAlgorithm only update.
    ///
    /// # Arguments
    /// hash_algorithm -- The HashingAlgorithm associated with the pcr selection
    /// pcr_slots      -- The PCR slots in the selection.
    pub fn with_selection(
        mut self,
        hash_algorithm: HashingAlgorithm,
        pcr_slots: &[PcrSlot],
    ) -> Self {
        // let selected_pcr_slots: BitFlags<PcrSlot> = pcr_slots.iter().cloned().collect();
        match self.items.get_mut(&hash_algorithm) {
            Some(previously_selected_pcr_slots) => {
                // *previously_selected_pcr_slots |= selected_pcr_slots;
                previously_selected_pcr_slots.extend_from_slice(pcr_slots);
            }
            None => {
                let _ = self.items.insert(hash_algorithm, pcr_slots.to_vec());
            }
        }
        self
    }

    /// Builds a PcrSelections with the values that have been
    /// provided.
    ///
    /// If no size of select have been provided then it will
    /// be defaulted to 3. This may not be the correct size for
    /// the current platform. The correct values can be obtained
    /// by quering the tpm for its capabilities.
    pub fn build(self) -> PcrSelectionList {
        let size_of_select = self.size_of_select.unwrap_or_default();
        PcrSelectionList {
            items: self
                .items
                .iter()
                .map(|(k, v)| PcrSelection::new(*k, size_of_select, v.as_slice()))
                .collect(),
        }
    }
}
