// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelectionListBuilder, PcrSlot},
};

mod test_pcr_selection_list {
    use super::*;
    #[test]
    fn test_subtract_remaining_values() {
        let mut pcr_selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        let pcr_selection_list_1 = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot8])
            .build();

        let expected = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build();

        pcr_selection_list.subtract(&pcr_selection_list_1).unwrap();

        assert_eq!(expected, pcr_selection_list);
    }

    #[test]
    fn test_subtract_nothing_remaining() {
        let mut pcr_selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        let pcr_selection_list_1 = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selection_list.subtract(&pcr_selection_list_1).unwrap();

        assert!(pcr_selection_list.is_empty());
    }

    #[test]
    fn test_subtract_with_non_equal_size_of_select_failure() {
        // pcr selections with 3 bytes size of select.
        let mut pcr_selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(PcrSelectSize::ThreeBytes)
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        // Pcr selections with 2 bytes size of select.
        let pcr_selection_list_1 = PcrSelectionListBuilder::new()
            .with_size_of_select(PcrSelectSize::TwoBytes)
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selection_list
            .subtract(&pcr_selection_list_1)
            .unwrap_err();
    }

    #[test]
    fn test_subtract_attempting_to_subtract_a_non_existant_value_failure() {
        // pcr selections
        let mut pcr_selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot8])
            .build();

        // Pcr selections with 1 more pcr slot then the previous.
        let pcr_selection_list_1 = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selection_list
            .subtract(&pcr_selection_list_1)
            .unwrap_err();
    }

    #[test]
    fn test_subtract_with_larg_selection_ramining_value() {
        // pcr selections
        let mut pcr_selection_list = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha1,
                &[
                    PcrSlot::Slot1,
                    PcrSlot::Slot3,
                    PcrSlot::Slot5,
                    PcrSlot::Slot7,
                ],
            )
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot7, PcrSlot::Slot8],
            )
            .with_selection(
                HashingAlgorithm::Sha512,
                &[
                    PcrSlot::Slot4,
                    PcrSlot::Slot8,
                    PcrSlot::Slot12,
                    PcrSlot::Slot16,
                ],
            )
            .build();

        let pcr_selection_list_1 = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha1,
                &[
                    PcrSlot::Slot1,
                    /*PcrSlot::Slot3, PcrSlot::Slot5,*/ PcrSlot::Slot7,
                ],
            )
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot7, PcrSlot::Slot8],
            )
            .with_selection(
                HashingAlgorithm::Sha512,
                &[
                    PcrSlot::Slot4,
                    PcrSlot::Slot8,
                    /*PcrSlot::Slot12,*/ PcrSlot::Slot16,
                ],
            )
            .build();

        let expected = PcrSelectionListBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot3, PcrSlot::Slot5])
            .with_selection(HashingAlgorithm::Sha512, &[PcrSlot::Slot12])
            .build();

        pcr_selection_list.subtract(&pcr_selection_list_1).unwrap();
        assert_eq!(expected, pcr_selection_list);
    }
}
