// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_field_upgrade_start {
    #[test]
    #[ignore = "TPM2_FieldUpgradeStart is not supported by swtpm"]
    fn test_field_upgrade_start() {
        // Unimplemented: swtpm does not support this command.
    }
}

mod test_field_upgrade_data {
    use crate::common::create_ctx_without_session;
    use tss_esapi::structures::MaxBuffer;

    #[test]
    #[ignore = "Field Upgrade Mode is not supported by swtpm"]
    fn test_field_upgrade_data() {
        // Not implemented: swtpm does not support Field Upgrade Mode (FUM).
    }

    #[test]
    fn test_field_upgrade_data_rejected_outside_fum() {
        let mut context = create_ctx_without_session();

        let result = context.field_upgrade_data(MaxBuffer::default());

        assert!(result.is_err());
    }
}

mod test_firmware_read {
    #[test]
    #[ignore = "TPM2_FirmwareRead is not supported by swtpm"]
    fn test_firmware_read() {
        // Unimplemented: swtpm does not support this command.
    }
}
