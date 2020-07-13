use std::convert::TryFrom;
use tss_esapi::algorithm::structures::SensitiveData;
use tss_esapi::tss2_esys::TPM2B_SENSITIVE_DATA;
// TPM2B_SENSITIVE_DATA has a max size of 256 bytes.
mod test_sensitive_data {
    use super::*;

    #[test]
    fn test_max_sized_data() {
        let _ = SensitiveData::try_from([0xff; 256].to_vec()).unwrap();
    }

    #[test]
    fn test_to_large_data() {
        // Removed:
        //    - test_create::test_long_init_data_create
        //    - test_create_primary::test_long_init_data_create_primary
        // from the context tests and put here instead.

        let _ = SensitiveData::try_from([0xa5; 300].to_vec()).unwrap_err();
    }
    #[test]
    fn test_default() {
        {
            let sensitive_data: SensitiveData = Default::default();
            let expected: TPM2B_SENSITIVE_DATA = Default::default();
            let actual = TPM2B_SENSITIVE_DATA::try_from(sensitive_data).unwrap();
            assert_eq!(expected.size, actual.size);
            assert_eq!(
                expected.buffer.len(),
                actual.buffer.len(),
                "Buffers don't have the same length"
            );
            assert!(
                expected
                    .buffer
                    .iter()
                    .zip(actual.buffer.iter())
                    .all(|(a, b)| a == b),
                "Buffers are not equal"
            );
        }
        {
            let tss_sensitive_data: TPM2B_SENSITIVE_DATA = Default::default();
            let expected: SensitiveData = Default::default();
            let actual = SensitiveData::try_from(tss_sensitive_data).unwrap();
            assert_eq!(expected, actual);
        }
    }
}
