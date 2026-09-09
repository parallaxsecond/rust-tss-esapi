// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_get_capability {
    use crate::common::create_ctx_without_session;
    use tss_esapi::{
        constants::{
            CapabilityType, PropertyTag,
            tss::{TPM2_PT_VENDOR_STRING_1, TPMA_CC_V},
        },
        structures::{CapabilityData, CommandCodeAttributesList},
    };

    #[test]
    fn test_get_capability() {
        let mut context = create_ctx_without_session();
        let (res, _more) = context
            .get_capability(CapabilityType::TpmProperties, TPM2_PT_VENDOR_STRING_1, 4)
            .unwrap();
        match res {
            CapabilityData::TpmProperties(props) => {
                assert_ne!(props.len(), 0);
            }
            _ => panic!("Invalid properties returned"),
        };
    }

    #[test]
    fn test_get_capability_commands() {
        let mut context = create_ctx_without_session();
        let expected_command_count = context
            .get_tpm_property(PropertyTag::TotalCommands)
            .expect("Failed to get total number of commands")
            .expect("TPM did not report the total number of commands");
        let mut property = 0;
        let mut command_count = 0;

        loop {
            let (capability_data, more_data_available) = context
                .get_capability(
                    CapabilityType::Command,
                    property,
                    CommandCodeAttributesList::MAX_SIZE as u32,
                )
                .expect("Failed to get command capabilities");

            let command_code_attributes = match capability_data {
                CapabilityData::Commands(command_code_attributes) => command_code_attributes,
                capability_data => panic!("Invalid capability data returned: {capability_data:?}"),
            };
            command_count += command_code_attributes.len();

            if !more_data_available {
                break;
            }

            let last_command_code_attributes = command_code_attributes
                .last()
                .expect("TPM indicated more data but returned no command capabilities");
            let vendor_specific = if last_command_code_attributes.is_vendor_specific() {
                TPMA_CC_V
            } else {
                0
            };
            let next_property =
                vendor_specific | (u32::from(last_command_code_attributes.command_index()) + 1);
            assert!(
                next_property > property,
                "TPM returned command capabilities without advancing the property"
            );
            property = next_property;
        }

        assert_eq!(
            command_count, expected_command_count as usize,
            "TPM did not return all command capabilities"
        );
    }

    #[test]
    fn test_get_tpm_property() {
        let mut context = create_ctx_without_session();

        let rev = context
            .get_tpm_property(PropertyTag::Revision)
            .expect("Failed to call get_tpm_property")
            .expect("The TPM did not have a value for the Reveision property tag");
        assert_ne!(rev, 0);

        let year = context
            .get_tpm_property(PropertyTag::Year)
            .expect("Failed to call get_tpm_property")
            .expect("The TPM did not have a value for the Year property tag");
        assert_ne!(year, 0);
    }
}
