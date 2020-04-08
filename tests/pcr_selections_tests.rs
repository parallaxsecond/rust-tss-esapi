use std::convert::TryFrom;
use tss_esapi::tss2_esys::{TPM2_ALG_ID, TPML_PCR_SELECTION};
use tss_esapi::utils::algorithm_specifiers::HashingAlgorithm;
use tss_esapi::utils::{PcrSelectionsBuilder, PcrSlot};

mod test_pcr_selection_builder {
    use super::*;

    #[test]
    fn test_one_selection() {
        let pcr_selections = PcrSelectionsBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .build();

        let actual: TPML_PCR_SELECTION = pcr_selections.into();
        assert_eq!(actual.count, 1);
        assert_eq!(actual.pcrSelections[0].sizeofSelect, 3);
        assert_eq!(
            actual.pcrSelections[0].hash,
            Into::<TPM2_ALG_ID>::into(HashingAlgorithm::Sha256)
        );
        assert_eq!(actual.pcrSelections[0].pcrSelect[0], 0b0000_0001);
        assert_eq!(actual.pcrSelections[0].pcrSelect[1], 0b0000_0001);
        assert_eq!(actual.pcrSelections[0].pcrSelect[2], 0b0000_0001);
    }

    #[test]
    fn test_multiple_selection() {
        let pcr_selections = PcrSelectionsBuilder::new()
            .with_selection(
                HashingAlgorithm::Sha256,
                &[PcrSlot::Slot0, PcrSlot::Slot8, PcrSlot::Slot16],
            )
            .with_selection(
                HashingAlgorithm::Sha1,
                &[
                    PcrSlot::Slot1,
                    PcrSlot::Slot8,
                    PcrSlot::Slot10,
                    PcrSlot::Slot20,
                    PcrSlot::Slot23,
                ],
            )
            .build();

        let actual: TPML_PCR_SELECTION = pcr_selections.into();
        assert_eq!(actual.count, 2);
        for index in 0..1 {
            let pcr_selection = &actual.pcrSelections[index as usize];
            assert_eq!(pcr_selection.sizeofSelect, 3);
            match HashingAlgorithm::try_from(pcr_selection.hash).unwrap() {
                HashingAlgorithm::Sha256 => {
                    assert_eq!(pcr_selection.pcrSelect[0], 0b0000_0001);
                    assert_eq!(pcr_selection.pcrSelect[1], 0b0000_0001);
                    assert_eq!(pcr_selection.pcrSelect[2], 0b0000_0001);
                }
                HashingAlgorithm::Sha1 => {
                    assert_eq!(pcr_selection.pcrSelect[0], 0b0000_0010);
                    assert_eq!(pcr_selection.pcrSelect[1], 0b0000_0101);
                    assert_eq!(pcr_selection.pcrSelect[2], 0b1001_0000);
                }
                _ => panic!("Encountered incorrect Hashing Algorithm"),
            }
        }
    }
}