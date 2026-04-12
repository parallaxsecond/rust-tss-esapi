// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_field_upgrade_start {
    #[test]
    #[ignore]
    fn test_field_upgrade_start() {
        // FieldUpgradeStart requires vendor-specific firmware upgrade data
        // and is not supported by standard TPM simulators.
    }
}

mod test_field_upgrade_data {
    #[test]
    #[ignore]
    fn test_field_upgrade_data() {
        // FieldUpgradeData requires an active field upgrade sequence
        // which is vendor-specific.
    }
}

mod test_firmware_read {
    #[test]
    #[ignore]
    fn test_firmware_read() {
        // FirmwareRead is vendor-specific and may not be supported
        // by standard TPM simulators.
    }
}
