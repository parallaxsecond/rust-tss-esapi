use tss_esapi::tss2_esys::{
    TPMS_CERTIFY_INFO, TPMS_CLOCK_INFO, TPMS_COMMAND_AUDIT_INFO, TPMS_PCR_SELECTION,
    TPMS_QUOTE_INFO, TPMS_SESSION_AUDIT_INFO, TPMS_TIME_ATTEST_INFO, TPMS_TIME_INFO,
};

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
        "'clock' value in TPMS_CLOCK_INFO, mismatch between actual and expected",
    );
    assert_eq!(
        expected.resetCount, actual.resetCount,
        "'resetCount' value in TPMS_CLOCK_INFO, mismatch between actual and expected",
    );
    assert_eq!(
        expected.restartCount, actual.restartCount,
        "'restartCount' value in TPMS_CLOCK_INFO, mismatch between actual and expected",
    );
    assert_eq!(
        expected.safe, actual.safe,
        "'safe' value in TPMS_CLOCK_INFO, mismatch between actual and expected",
    );
}

#[allow(dead_code)]
pub fn ensure_tpms_quote_info_equality(expected: &TPMS_QUOTE_INFO, actual: &TPMS_QUOTE_INFO) {
    ensure_sized_buffer_field_equality!(expected, actual, pcrDigest, buffer, TPM2B_DIGEST);
    crate::common::ensure_tpml_pcr_selection_equality(&expected.pcrSelect, &actual.pcrSelect);
}

#[allow(dead_code)]
pub fn ensure_tpms_pcr_selection_equality(
    expected: &TPMS_PCR_SELECTION,
    actual: &TPMS_PCR_SELECTION,
) {
    assert_eq!(
        expected.hash, actual.hash,
        "'hash' value in TPMS_PCR_SELECTION, mismatch between actual and expected",
    );
    assert_eq!(
        expected.sizeofSelect, actual.sizeofSelect,
        "'sizeofSelect' value in TPMS_PCR_SELECTION, mismatch between actual and expected",
    );
    assert_eq!(
        expected.pcrSelect, actual.pcrSelect,
        "'pcrSelect' value in TPMS_PCR_SELECTION, mismatch between actual and expected",
    );
}

#[allow(dead_code)]
pub fn ensure_tpms_time_info_equality(expected: &TPMS_TIME_INFO, actual: &TPMS_TIME_INFO) {
    assert_eq!(
        expected.time, actual.time,
        "'time' value in TPMS_TIME_INFO, mismatch between actual and expected",
    );
    ensure_tpms_clock_info_equality(&expected.clockInfo, &actual.clockInfo);
}

#[allow(dead_code)]
pub fn ensure_tpms_time_attest_info_equality(
    expected: &TPMS_TIME_ATTEST_INFO,
    actual: &TPMS_TIME_ATTEST_INFO,
) {
    ensure_tpms_time_info_equality(&expected.time, &actual.time);
    assert_eq!(
        expected.firmwareVersion, actual.firmwareVersion,
        "'firmwareVersion' value in TPMS_TIME_ATTEST_INFO, mismatch between actual and expected",
    );
}

#[allow(dead_code)]
pub fn ensure_tpms_command_audit_info_equality(
    expected: &TPMS_COMMAND_AUDIT_INFO,
    actual: &TPMS_COMMAND_AUDIT_INFO,
) {
    assert_eq!(
        expected.auditCounter, actual.auditCounter,
        "'auditCounter' value in TPMS_COMMAND_AUDIT_INFO, mismatch between actual and expected",
    );
    assert_eq!(
        expected.digestAlg, actual.digestAlg,
        "'digestAlg' value in TPMS_COMMAND_AUDIT_INFO, mismatch between actual and expected",
    );
    ensure_sized_buffer_field_equality!(expected, actual, auditDigest, buffer, TPM2B_DIGEST);
    ensure_sized_buffer_field_equality!(expected, actual, commandDigest, buffer, TPM2B_DIGEST);
}

#[allow(dead_code)]
pub fn ensure_tpms_session_audit_info_equality(
    expected: &TPMS_SESSION_AUDIT_INFO,
    actual: &TPMS_SESSION_AUDIT_INFO,
) {
    assert_eq!(
        expected.exclusiveSession, actual.exclusiveSession,
        "'exclusiveSession' value in TPMS_SESSION_AUDIT_INFO, mismatch between actual and expected",
    );
    ensure_sized_buffer_field_equality!(expected, actual, sessionDigest, buffer, TPM2B_DIGEST);
}
