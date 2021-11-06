use tss_esapi::tss2_esys::{TPMS_CERTIFY_INFO, TPMS_CLOCK_INFO};

macro_rules! ensure_sized_buffer_field_equality {
    ($expected:ident, $actual:ident, $field_name:ident, $buffer_field_name:ident, $tss_type:ident) => {
        assert_eq!(
            $expected.$field_name.size,
            $actual.$field_name.size,
            "'size' value for {} field in {}, mismatch between actual and expected",
            stringify!($field_name),
            stringify!($tss_type),
        );
        assert_eq!(
            $expected.$field_name.$buffer_field_name,
            $actual.$field_name.$buffer_field_name,
            "'{}' value for {} field in {}, mismatch between actual and expected",
            stringify!($buffer_field_name),
            stringify!($field_name),
            stringify!($tss_type),
        );
    };
}

#[allow(dead_code)]
pub fn ensure_tpms_certify_info_equality(expected: &TPMS_CERTIFY_INFO, actual: &TPMS_CERTIFY_INFO) {
    ensure_sized_buffer_field_equality!(expected, actual, name, name, TPM2B_NAME);
    ensure_sized_buffer_field_equality!(expected, actual, qualifiedName, name, TPM2B_NAME);
}

#[allow(dead_code)]
pub fn ensure_tpms_clock_info_equality(expected: &TPMS_CLOCK_INFO, actual: &TPMS_CLOCK_INFO) {
    assert_eq!(
        expected.clock, actual.clock,
        "'clock' value in TPMS_CLOCK_INFO, mismatch between aactual and expected",
    );
    assert_eq!(
        expected.resetCount, actual.resetCount,
        "'resetCount' value in TPMS_CLOCK_INFO, mismatch between aactual and expected",
    );
    assert_eq!(
        expected.restartCount, actual.restartCount,
        "'restartCount' value in TPMS_CLOCK_INFO, mismatch between aactual and expected",
    );
    assert_eq!(
        expected.safe, actual.safe,
        "'safe' value in TPMS_CLOCK_INFO, mismatch between aactual and expected",
    );
}
