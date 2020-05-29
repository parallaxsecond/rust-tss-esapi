use tss_esapi::utils::algorithm_specifiers::HashingAlgorithm;
use tss_esapi::utils::{PcrSelectSize, PcrSelectionsBuilder, PcrSlot};

mod test_pcr_selections {
    use super::*;
    #[test]
    fn test_subtract_remaining_values() {
        let mut pcr_selections = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        let pcr_selections_1 = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot8])
            .build();

        let expected = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot16])
            .build();

        pcr_selections.subtract(&pcr_selections_1).unwrap();

        assert_eq!(expected, pcr_selections);
    }

    #[test]
    fn test_subtract_nothing_remaining() {
        let mut pcr_selections = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        let pcr_selections_1 = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selections.subtract(&pcr_selections_1).unwrap();

        assert_eq!(true, pcr_selections.is_empty());
    }

    #[test]
    fn test_subtract_with_non_equal_size_of_select_failure() {
        // pcr selections with 3 bytes size of select.
        let mut pcr_selections = PcrSelectionsBuilder::new()
            .with_size_of_select(PcrSelectSize::ThreeBytes)
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        // Pcr selections with 2 bytes size of select.
        let pcr_selections_1 = PcrSelectionsBuilder::new()
            .with_size_of_select(PcrSelectSize::TwoBytes)
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selections.subtract(&pcr_selections_1).unwrap_err();
    }

    #[test]
    fn test_subtract_attempting_to_subtract_a_non_existant_value_failure() {
        // pcr selections
        let mut pcr_selections = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0, PcrSlot::Slot8])
            .build();

        // Pcr selections with 1 more pcr slot then the previous.
        let pcr_selections_1 = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        pcr_selections.subtract(&pcr_selections_1).unwrap_err();
    }

    #[test]
    fn test_subtract_with_larg_selection_ramining_value() {
        // pcr selections
        let mut pcr_selections = PcrSelectionsBuilder::new()
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

        let pcr_selections_1 = PcrSelectionsBuilder::new()
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

        let expected = PcrSelectionsBuilder::new()
            .with_size_of_select(Default::default())
            .with_selection(HashingAlgorithm::Sha1, &[PcrSlot::Slot3, PcrSlot::Slot5])
            .with_selection(HashingAlgorithm::Sha512, &[PcrSlot::Slot12])
            .build();

        pcr_selections.subtract(&pcr_selections_1).unwrap();
        assert_eq!(expected, pcr_selections);
    }
}
