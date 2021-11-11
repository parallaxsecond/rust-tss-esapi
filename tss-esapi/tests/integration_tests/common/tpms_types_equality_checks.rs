use tss_esapi::{
    constants::tss::{
        TPM2_ST_ATTEST_CERTIFY, TPM2_ST_ATTEST_COMMAND_AUDIT, TPM2_ST_ATTEST_CREATION,
        TPM2_ST_ATTEST_NV, TPM2_ST_ATTEST_QUOTE, TPM2_ST_ATTEST_SESSION_AUDIT, TPM2_ST_ATTEST_TIME,
    },
    tss2_esys::{
        TPMS_ATTEST, TPMS_CERTIFY_INFO, TPMS_CLOCK_INFO, TPMS_COMMAND_AUDIT_INFO,
        TPMS_CREATION_INFO, TPMS_NV_CERTIFY_INFO, TPMS_PCR_SELECTION, TPMS_QUOTE_INFO,
        TPMS_SESSION_AUDIT_INFO, TPMS_TIME_ATTEST_INFO, TPMS_TIME_INFO,
    },
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

#[allow(dead_code)]
pub fn ensure_tpms_creation_info_equality(
    expected: &TPMS_CREATION_INFO,
    actual: &TPMS_CREATION_INFO,
) {
    ensure_sized_buffer_field_equality!(expected, actual, objectName, name, TPM2B_NAME);
    ensure_sized_buffer_field_equality!(expected, actual, creationHash, buffer, TPM2B_DIGEST);
}

#[allow(dead_code)]
pub fn ensure_tpms_nv_certify_info_equality(
    expected: &TPMS_NV_CERTIFY_INFO,
    actual: &TPMS_NV_CERTIFY_INFO,
) {
    ensure_sized_buffer_field_equality!(expected, actual, indexName, name, TPM2B_NAME);
    assert_eq!(
        expected.offset, actual.offset,
        "'offset' value in TPMS_NV_CERTIFY_INFO, mismatch between actual and expected",
    );
    ensure_sized_buffer_field_equality!(expected, actual, nvContents, buffer, TPM2B_MAX_NV_BUFFER);
}

#[allow(dead_code)]
pub fn ensure_tpms_attest_equality(expected: &TPMS_ATTEST, actual: &TPMS_ATTEST) {
    assert_eq!(
        expected.magic, actual.magic,
        "'magic' value in TPMS_ATTEST, mismatch between actual and expected"
    );
    assert_eq!(
        expected.type_, actual.type_,
        "'type_' value in TPMS_ATTEST, mismatch between actual and expected",
    );
    ensure_sized_buffer_field_equality!(expected, actual, qualifiedSigner, name, TPM2B_NAME);
    ensure_sized_buffer_field_equality!(expected, actual, extraData, buffer, TPM2B_DATA);
    ensure_tpms_clock_info_equality(&expected.clockInfo, &actual.clockInfo);
    assert_eq!(
        expected.firmwareVersion, actual.firmwareVersion,
        "'firmwareVersion' value in TPMS_ATTEST, mismatch between actual and expected",
    );
    match expected.type_ {
        TPM2_ST_ATTEST_CERTIFY => {
            ensure_tpms_certify_info_equality(unsafe { &expected.attested.certify }, unsafe {
                &actual.attested.certify
            });
        }
        TPM2_ST_ATTEST_QUOTE => {
            ensure_tpms_quote_info_equality(unsafe { &expected.attested.quote }, unsafe {
                &actual.attested.quote
            });
        }
        TPM2_ST_ATTEST_SESSION_AUDIT => ensure_tpms_session_audit_info_equality(
            unsafe { &expected.attested.sessionAudit },
            unsafe { &actual.attested.sessionAudit },
        ),
        TPM2_ST_ATTEST_COMMAND_AUDIT => ensure_tpms_command_audit_info_equality(
            unsafe { &expected.attested.commandAudit },
            unsafe { &actual.attested.commandAudit },
        ),
        TPM2_ST_ATTEST_TIME => {
            ensure_tpms_time_attest_info_equality(unsafe { &expected.attested.time }, unsafe {
                &actual.attested.time
            })
        }
        TPM2_ST_ATTEST_CREATION => {
            ensure_tpms_creation_info_equality(unsafe { &expected.attested.creation }, unsafe {
                &actual.attested.creation
            })
        }
        TPM2_ST_ATTEST_NV => {
            ensure_tpms_nv_certify_info_equality(unsafe { &expected.attested.nv }, unsafe {
                &actual.attested.nv
            })
        }
        _ => panic!("'type_' value in TPMS_ATTEST contained invalid or unsupported value"),
    }
}
