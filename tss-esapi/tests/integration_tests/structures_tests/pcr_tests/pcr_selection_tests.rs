// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_ALG_SHA256, TPM2_ALG_SHA512},
    interface_types::algorithm::HashingAlgorithm,
    structures::{PcrSelectSize, PcrSelection, PcrSlot},
    tss2_esys::TPMS_PCR_SELECTION,
};

#[test]
fn test_conversion_to_tss_pcr_selection() {
    let actual = TPMS_PCR_SELECTION::try_from(
        PcrSelection::create(
            HashingAlgorithm::Sha512,
            PcrSelectSize::ThreeBytes,
            &[PcrSlot::Slot3, PcrSlot::Slot9, PcrSlot::Slot23],
        )
        .expect("Failed to create pcr selection"),
    )
    .expect("Failed to convert PcrSelection to TPMS_PCR_SELECTION");
    let expected = TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA512,
        sizeofSelect: 3,
        pcrSelect: [8, 2, 128, 0],
    };
    assert_eq!(expected.hash, actual.hash);
    assert_eq!(expected.sizeofSelect, actual.sizeofSelect);
    assert_eq!(expected.pcrSelect, actual.pcrSelect);
}

#[test]
fn test_conversion_from_tss_pcr_selection() {
    let actual = PcrSelection::try_from(TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA256,
        sizeofSelect: 2,
        pcrSelect: [16, 128, 0, 0],
    })
    .unwrap();
    let expected = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoBytes,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create pcr selection");
    assert_eq!(expected, actual);
}

#[test]
fn test_size_of_select_handling() {
    let actual = PcrSelection::try_from(TPMS_PCR_SELECTION {
        hash: TPM2_ALG_SHA256,
        sizeofSelect: 2,
        pcrSelect: [16, 128, 5, 1],
    })
    .expect("Failed to convert TPMS_PCR_SELECTION into a PcrSelection");

    // Size of select is 2 so the values in octet 3 and 4
    // should not appear in the converted pcr selection.

    let expected = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoBytes,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create PcrSelection");
    assert_eq!(expected, actual);
}

#[test]
fn test_subtract() {
    let mut pcr_select_1 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoBytes,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    )
    .expect("Failed to create PcrSelect pcr_select_1");

    let pcr_select_2 = PcrSelection::create(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoBytes,
        &[PcrSlot::Slot4],
    )
    .expect("Failed to create PcrSelect pcr_select_2");

    pcr_select_1
        .subtract_exact(&pcr_select_2)
        .expect("Failed to subtract pcr_select_2 from pcr_select_1");

    assert_eq!(
        pcr_select_1.hashing_algorithm(),
        HashingAlgorithm::Sha256,
        "The pcr_select_1 did not contain expected HashingAlgorithm after subtract"
    );

    assert_eq!(
        pcr_select_1.size_of_select(),
        PcrSelectSize::TwoBytes,
        "The pcr_select_1 did not have the expected size of select after subtract"
    );

    assert_eq!(
        pcr_select_1.selected(),
        vec![PcrSlot::Slot15],
        "The pcr_select_1 did not contain expected PcrSlots after subtract"
    );
}
