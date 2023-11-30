// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

macro_rules! test_conversions {
    ($tss_key_bits_interface_type:ident, $value:expr, $interface_type:ident::$interface_type_item:ident) => {
        let expected_interface_type = $tss_key_bits_interface_type::from($value);
        assert_eq!(
            expected_interface_type,
            $tss_key_bits_interface_type::from($interface_type::$interface_type_item)
        );
        assert_eq!(
            $interface_type::try_from(expected_interface_type).unwrap_or_else(|_| {
                panic!(
                    "It should be possible to convert from {} to {}.",
                    std::any::type_name::<$interface_type>(),
                    expected_interface_type
                );
            }),
            $interface_type::$interface_type_item,
        );
    };
}

macro_rules! test_invalid_conversions {
    ($tss_ket_bits_interface_type:ident, $value:expr, $interface_type:ident, WrapperErrorKind::$expected_error:ident) => {
        assert_eq!(
            $interface_type::try_from($value as $tss_ket_bits_interface_type),
            Err(tss_esapi::Error::WrapperError(
                tss_esapi::WrapperErrorKind::$expected_error
            )),
        );
    };
}

mod aes_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::AesKeyBits, tss2_esys::TPMI_AES_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_AES_KEY_BITS, 128u16, AesKeyBits::Aes128);
        test_conversions!(TPMI_AES_KEY_BITS, 192u16, AesKeyBits::Aes192);
        test_conversions!(TPMI_AES_KEY_BITS, 256u16, AesKeyBits::Aes256);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            0,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            129,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            193,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_AES_KEY_BITS,
            257,
            AesKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod sm4_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::Sm4KeyBits, tss2_esys::TPMI_SM4_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_SM4_KEY_BITS, 128u16, Sm4KeyBits::Sm4_128);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_SM4_KEY_BITS,
            0u16,
            Sm4KeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_SM4_KEY_BITS,
            129u16,
            Sm4KeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod camellia_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::CamelliaKeyBits, tss2_esys::TPM2_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPM2_KEY_BITS, 128u16, CamelliaKeyBits::Camellia128);
        test_conversions!(TPM2_KEY_BITS, 192u16, CamelliaKeyBits::Camellia192);
        test_conversions!(TPM2_KEY_BITS, 256u16, CamelliaKeyBits::Camellia256);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPM2_KEY_BITS,
            0u16,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            129u16,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            193u16,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPM2_KEY_BITS,
            257u16,
            CamelliaKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}

mod rsa_key_bits_tests {
    use std::convert::TryFrom;
    use tss_esapi::{interface_types::key_bits::RsaKeyBits, tss2_esys::TPMI_RSA_KEY_BITS};

    #[test]
    fn test_valid_conversions() {
        test_conversions!(TPMI_RSA_KEY_BITS, 1024u16, RsaKeyBits::Rsa1024);
        test_conversions!(TPMI_RSA_KEY_BITS, 2048u16, RsaKeyBits::Rsa2048);
        test_conversions!(TPMI_RSA_KEY_BITS, 3072u16, RsaKeyBits::Rsa3072);
        test_conversions!(TPMI_RSA_KEY_BITS, 4096u16, RsaKeyBits::Rsa4096);
    }

    #[test]
    fn test_invalid_conversions() {
        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            0u16,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            1025u16,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            2049u16,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            2073u16,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );

        test_invalid_conversions!(
            TPMI_RSA_KEY_BITS,
            4097u16,
            RsaKeyBits,
            WrapperErrorKind::InvalidParam
        );
    }
}
