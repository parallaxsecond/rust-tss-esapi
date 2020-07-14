// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    structures::{PcrSelect, PcrSelectSize, PcrSlot},
    tss2_esys::TPMS_PCR_SELECT,
};

mod test_pcr_select {
    use super::*;

    #[test]
    fn test_conversion_to_tss_pcr_select() {
        let actual = TPMS_PCR_SELECT::try_from(PcrSelect::new(
            PcrSelectSize::TwoBytes,
            &[PcrSlot::Slot0, PcrSlot::Slot8],
        ))
        .unwrap();
        let expected = TPMS_PCR_SELECT {
            sizeofSelect: 2,
            pcrSelect: [1, 1, 0, 0],
        };
        assert_eq!(expected.sizeofSelect, actual.sizeofSelect);
        assert_eq!(expected.pcrSelect, actual.pcrSelect);
    }

    #[test]
    fn test_conversion_from_tss_pcr_select() {
        let actual = PcrSelect::try_from(TPMS_PCR_SELECT {
            sizeofSelect: 3,
            pcrSelect: [2, 1, 3, 0],
        })
        .unwrap();
        let expected = PcrSelect::new(
            PcrSelectSize::ThreeBytes,
            &[
                PcrSlot::Slot1,
                PcrSlot::Slot8,
                PcrSlot::Slot16,
                PcrSlot::Slot17,
            ],
        );
        assert_eq!(expected, actual);
    }
}
