use tss_esapi::tss2_esys::TPML_PCR_SELECTION;

#[allow(dead_code)]
pub fn ensure_tpml_pcr_selection_equality(
    expected: &TPML_PCR_SELECTION,
    actual: &TPML_PCR_SELECTION,
) {
    assert_eq!(
        expected.count, actual.count,
        "'count' value in TPML_PCR_SELECTION, mismatch between aactual and expected",
    );
    expected.pcrSelections[..expected.count as usize]
        .iter()
        .zip(actual.pcrSelections[..actual.count as usize].iter())
        .for_each(|(expected_pcr_selection, actual_pcr_selection)| {
            crate::common::ensure_tpms_pcr_selection_equality(
                expected_pcr_selection,
                actual_pcr_selection,
            )
        });
}
