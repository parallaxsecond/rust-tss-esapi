// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelection, PcrSelectionList, PcrSlot},
    tss2_esys::{TPML_PCR_SELECTION, TPMS_PCR_SELECTION},
};

mod test_pcr_selection_list {
    use super::*;

    #[test]
    fn from_tpml_retains_order() {
        let selection_1 = PcrSelection::new(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeBytes,
            &[PcrSlot::Slot10],
        );
        let selection_1 = TPMS_PCR_SELECTION::try_from(selection_1).unwrap();

        let selection_2 = PcrSelection::new(
            HashingAlgorithm::Sha256,
            PcrSelectSize::ThreeBytes,
            &[PcrSlot::Slot11],
        );
        let selection_2 = TPMS_PCR_SELECTION::try_from(selection_2).unwrap();

        let selection_3 = PcrSelection::new(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeBytes,
            &[PcrSlot::Slot16],
        );
        let selection_3 = TPMS_PCR_SELECTION::try_from(selection_3).unwrap();

        let selection_4 = PcrSelection::new(
            HashingAlgorithm::Sha1,
            PcrSelectSize::ThreeBytes,
            &[PcrSlot::Slot2],
        );
        let selection_4 = TPMS_PCR_SELECTION::try_from(selection_4).unwrap();

        let empty_selection =
            PcrSelection::new(HashingAlgorithm::Sha1, PcrSelectSize::ThreeBytes, &[]);
        let empty_selection = TPMS_PCR_SELECTION::try_from(empty_selection).unwrap();

        let tpml_selections = TPML_PCR_SELECTION {
            count: 4,
            pcrSelections: [
                selection_1,
                selection_2,
                selection_3,
                selection_4,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
                empty_selection,
            ],
        };

        let selections = PcrSelectionList::try_from(tpml_selections).unwrap();
        let tpml_selections = TPML_PCR_SELECTION::try_from(selections).unwrap();
        let selections = PcrSelectionList::try_from(tpml_selections).unwrap();

        assert_eq!(selections.len(), 4);

        let sel_1 = selections.get_selections()[0];
        let sel_2 = selections.get_selections()[1];
        let sel_3 = selections.get_selections()[2];
        let sel_4 = selections.get_selections()[3];

        assert_eq!(sel_1.hashing_algorithm(), HashingAlgorithm::Sha256);
        assert!(!sel_1.is_empty());
        assert!(sel_1.selected_pcrs().contains(PcrSlot::Slot10));
        assert!(!sel_1.selected_pcrs().contains(PcrSlot::Slot11));

        assert_eq!(sel_2.hashing_algorithm(), HashingAlgorithm::Sha256);
        assert!(!sel_2.is_empty());
        assert!(sel_2.selected_pcrs().contains(PcrSlot::Slot11));

        assert_eq!(sel_3.hashing_algorithm(), HashingAlgorithm::Sha1);
        assert!(!sel_3.is_empty());
        assert!(sel_3.selected_pcrs().contains(PcrSlot::Slot16));

        assert_eq!(sel_4.hashing_algorithm(), HashingAlgorithm::Sha1);
        assert!(!sel_4.is_empty());
        assert!(sel_4.selected_pcrs().contains(PcrSlot::Slot2));
    }
}
