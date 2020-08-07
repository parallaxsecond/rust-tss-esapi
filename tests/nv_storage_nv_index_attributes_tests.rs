// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use tss_esapi::nv::storage::{NvIndexAttributes, NvIndexType};

mod test_nv_storage_nv_index_attributes {
    use super::*;

    #[test]
    fn test_invalid_index_type_value() {
        // 15(1111) - invalid
        let invalid_15 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1111_0000u32);
        let _ = invalid_15.index_type().unwrap_err();

        // 14(1110) - invalid
        let invalid_14 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1110_0000u32);
        let _ = invalid_14.index_type().unwrap_err();

        // 13(1101) - invalid
        let invalid_13 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1101_0000u32);
        let _ = invalid_13.index_type().unwrap_err();

        // 12(1100) - invalid
        let invalid_12 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1100_0000u32);
        let _ = invalid_12.index_type().unwrap_err();

        // 11(1011) - invalid
        let invalid_11 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1011_0000u32);
        let _ = invalid_11.index_type().unwrap_err();

        // 10(1010) - invalid
        let invalid_10 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_1011_0000u32);
        let _ = invalid_10.index_type().unwrap_err();

        // 9(1001) - Valid

        // 8(1000) - Valid

        // 7(0111) - invalid
        let invalid_7 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0111_0000u32);
        let _ = invalid_7.index_type().unwrap_err();

        // 6(0110) - invalid
        let invalid_6 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0110_0000u32);
        let _ = invalid_6.index_type().unwrap_err();

        // 5(0101) - invalid
        let invalid_5 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0101_0000u32);
        let _ = invalid_5.index_type().unwrap_err();

        // 4(0100) - valid

        // 3(0011) - invalid
        let invalid_3 = NvIndexAttributes(0b0000_0000_0000_0000_0000_0000_0011_0000u32);
        let _ = invalid_3.index_type().unwrap_err();

        // 2(0010) - valid

        // 1(0001) - valid

        // 0(0000) - valid
    }

    #[test]
    fn test_attributes() {
        let mut attributes = NvIndexAttributes(0x0);

        attributes.set_pp_write(true);
        assert_eq!(0b0000_0000_0000_0000_0000_0000_0000_0001u32, attributes.0);

        attributes.set_owner_write(true);
        assert_eq!(0b0000_0000_0000_0000_0000_0000_0000_0011u32, attributes.0);

        attributes.set_auth_write(true);
        assert_eq!(0b0000_0000_0000_0000_0000_0000_0000_0111u32, attributes.0);

        attributes.set_policy_write(true);
        assert_eq!(0b0000_0000_0000_0000_0000_0000_0000_1111u32, attributes.0);

        // PinPass = 1001 (7,4)
        attributes.set_index_type(NvIndexType::PinPass);
        assert_eq!(0b0000_0000_0000_0000_0000_0000_1001_1111u32, attributes.0);
        assert_eq!(NvIndexType::PinPass, attributes.index_type().unwrap());

        // (8,9 Reserved)
        attributes.set_policy_delete(true);
        assert_eq!(0b0000_0000_0000_0000_0000_0100_1001_1111u32, attributes.0);

        attributes.set_write_locked(true);
        assert_eq!(0b0000_0000_0000_0000_0000_1100_1001_1111u32, attributes.0);

        attributes.set_write_all(true);
        assert_eq!(0b0000_0000_0000_0000_0001_1100_1001_1111u32, attributes.0);

        attributes.set_write_define(true);
        assert_eq!(0b0000_0000_0000_0000_0011_1100_1001_1111u32, attributes.0);

        attributes.set_write_stclear(true);
        assert_eq!(0b0000_0000_0000_0000_0111_1100_1001_1111u32, attributes.0);

        attributes.set_global_lock(true);
        assert_eq!(0b0000_0000_0000_0000_1111_1100_1001_1111u32, attributes.0);

        attributes.set_pp_read(true);
        assert_eq!(0b0000_0000_0000_0001_1111_1100_1001_1111u32, attributes.0);

        attributes.set_owner_read(true);
        assert_eq!(0b0000_0000_0000_0011_1111_1100_1001_1111u32, attributes.0);

        attributes.set_auth_read(true);
        assert_eq!(0b0000_0000_0000_0111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_policy_read(true);
        assert_eq!(0b0000_0000_0000_1111_1111_1100_1001_1111u32, attributes.0);

        // Reserved (24, 20)
        attributes.set_no_da(true);
        assert_eq!(0b0000_0010_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_orderly(true);
        assert_eq!(0b0000_0110_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_clear_stclear(true);
        assert_eq!(0b0000_1110_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_read_locked(true);
        assert_eq!(0b0001_1110_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_written(true);
        assert_eq!(0b0011_1110_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_platform_create(true);
        assert_eq!(0b0111_1110_0000_1111_1111_1100_1001_1111u32, attributes.0);

        attributes.set_read_stclear(true);
        assert_eq!(0b1111_1110_0000_1111_1111_1100_1001_1111u32, attributes.0);
    }
}
