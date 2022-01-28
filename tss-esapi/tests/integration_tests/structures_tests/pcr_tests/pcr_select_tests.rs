// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    structures::{PcrSelect, PcrSelectSize, PcrSlot},
    tss2_esys::TPMS_PCR_SELECT,
};

#[test]
fn test_conversion_to_tss_pcr_select() {
    let actual = TPMS_PCR_SELECT::try_from(
        PcrSelect::create(PcrSelectSize::TwoBytes, &[PcrSlot::Slot0, PcrSlot::Slot8])
            .expect("Failed to create PcrSelect"),
    )
    .expect("Failed to convert PcrSelect into TPMS_PCR_SELECT");
    let expected = TPMS_PCR_SELECT {
        sizeofSelect: 2,
        pcrSelect: [1, 1, 0, 0],
    };
    assert_eq!(expected.sizeofSelect, actual.sizeofSelect);
    assert_eq!(expected.pcrSelect, actual.pcrSelect);
}

#[test]
fn test_size_of_select_handling() {
    let actual = PcrSelect::try_from(TPMS_PCR_SELECT {
        sizeofSelect: 3,
        pcrSelect: [2, 1, 3, 5],
    })
    .expect("Failed to convert TPMS_PCR_SELECT to PcrSelect");
    // Size of select is 3 so no values set in the fourth
    // octet should be present.
    let expected = PcrSelect::create(
        PcrSelectSize::ThreeBytes,
        &[
            PcrSlot::Slot1,
            PcrSlot::Slot8,
            PcrSlot::Slot16,
            PcrSlot::Slot17,
        ],
    )
    .expect("Failed to create PcrSelect");
    assert_eq!(expected, actual);
}

#[test]
fn test_conversion_from_tss_pcr_select() {
    let actual = PcrSelect::try_from(TPMS_PCR_SELECT {
        sizeofSelect: 3,
        pcrSelect: [2, 1, 3, 0],
    })
    .unwrap();
    let expected = PcrSelect::create(
        PcrSelectSize::ThreeBytes,
        &[
            PcrSlot::Slot1,
            PcrSlot::Slot8,
            PcrSlot::Slot16,
            PcrSlot::Slot17,
        ],
    )
    .expect("Failed to create PcrSelect");
    assert_eq!(expected, actual);
}
