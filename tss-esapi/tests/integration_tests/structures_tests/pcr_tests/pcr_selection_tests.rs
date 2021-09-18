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
    let actual = TPMS_PCR_SELECTION::try_from(PcrSelection::new(
        HashingAlgorithm::Sha512,
        PcrSelectSize::ThreeBytes,
        &[PcrSlot::Slot3, PcrSlot::Slot9, PcrSlot::Slot23],
    ))
    .unwrap();
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
    let expected = PcrSelection::new(
        HashingAlgorithm::Sha256,
        PcrSelectSize::TwoBytes,
        &[PcrSlot::Slot4, PcrSlot::Slot15],
    );
    assert_eq!(expected, actual);
}
