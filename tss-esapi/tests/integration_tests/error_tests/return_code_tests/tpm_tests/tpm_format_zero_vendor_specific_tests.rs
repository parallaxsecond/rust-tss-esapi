// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use bitfield::bitfield;
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_RC_INITIALIZE, TSS2_TPM_RC_LAYER},
    error::{ReturnCode, TpmFormatZeroResponseCode, TpmResponseCode},
};

bitfield! {
    pub struct VendorSpecificBitHelper(u32);
    _, set_is_vendor_specific: 10;
}

#[test]
fn test_valid_conversions() {
    // Bit 10 In the TPM format zero return code is the bit indicating vendor specific.
    // |11|10| 9|   8   | 7| 6| 5| 4| 3| 2| 1| 0|
    // | W| V| R|TPM 2.0|  |    error number    |
    let mut helper = VendorSpecificBitHelper(TSS2_TPM_RC_LAYER | TPM2_RC_INITIALIZE);
    helper.set_is_vendor_specific(true);
    let expected_tss_rc = helper.0;

    let actual_rc = ReturnCode::try_from(expected_tss_rc)
        .expect("Failed to convert TPM zero error return code value with vendor specific bit set into a Result.");

    if let ReturnCode::Tpm(TpmResponseCode::FormatZero(
        TpmFormatZeroResponseCode::VendorSpecific(actual),
    )) = actual_rc
    {
        assert_eq!(
            expected_tss_rc,
            actual.into(),
            "Converting vendor specific return code did not return the original value."
        );
    } else {
        panic!("TPM TSS2_RC layer did no convert into ReturnCode::Tpm");
    }

    assert_eq!(
        expected_tss_rc,
        actual_rc.into(),
        "The vendor specific return code did not convert into the expected TSS2_RC in the TPM layer."
    )
}
