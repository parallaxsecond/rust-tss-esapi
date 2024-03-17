use std::convert::TryFrom;
use tss_esapi::{
    handles::TpmHandle,
    interface_types::{data_handles::Saved, reserved_handles::Hierarchy},
    structures::{SavedTpmContext, TpmContextData},
    tss2_esys::TPMS_CONTEXT,
};

#[test]
fn test_valid_conversions() {
    let expected_sequence = 13243546576879u64;
    let expected_saved_handle = Saved::Transient;
    let expected_hierarchy = Hierarchy::Owner;
    let expected_context_blob =
        TpmContextData::try_from(vec![1u8, 2u8, 12u8, 23u8, 45u8, 56u8, 98u8])
            .expect("It should be possible to create TpmContextData buffer type from bytes.");
    let expected_tpms_context = TPMS_CONTEXT {
        sequence: expected_sequence,
        savedHandle: expected_saved_handle.into(),
        hierarchy: TpmHandle::from(expected_hierarchy).into(),
        contextBlob: expected_context_blob.clone().into(),
    };
    // Conversion TPMS_CONTEXT -> SavedTpmContext
    let actual_saved_tpm_context = SavedTpmContext::try_from(expected_tpms_context).expect(
        "It should be possible to convert a valid TPMS_CONTEXT structure into a SavedTpmContext",
    );
    assert_eq!(expected_sequence, actual_saved_tpm_context.sequence());
    assert_eq!(
        expected_saved_handle,
        actual_saved_tpm_context.saved_handle()
    );
    assert_eq!(expected_hierarchy, actual_saved_tpm_context.hierarchy());
    assert_eq!(
        expected_context_blob,
        *actual_saved_tpm_context.context_blob()
    );
    // SavedTpmContext -> TPMS_CONTEXT
    let actual_tpms_context = TPMS_CONTEXT::from(actual_saved_tpm_context);
    crate::common::ensure_tpms_context_equality(&expected_tpms_context, &actual_tpms_context);
}
