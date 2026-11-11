// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_dictionary_attack_lock_reset {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{constants::PropertyTag, handles::AuthHandle};

    #[test]
    fn test_dictionary_attack_lock_reset() {
        let mut context = create_ctx_with_session();
        context
            .dictionary_attack_lock_reset(AuthHandle::Lockout)
            .expect("Failed to reset dictionary attack lockout");

        let lockout_counter = context
            .get_tpm_property(PropertyTag::LockoutCounter)
            .expect("Failed to get dictionary attack lockout counter")
            .expect("TPM did not report the dictionary attack lockout counter");
        assert_eq!(0, lockout_counter);
    }
}

mod test_dictionary_attack_parameters {
    use crate::common::create_ctx_with_session;
    use tss_esapi::{
        Context,
        constants::{CapabilityType, PropertyTag},
        handles::AuthHandle,
        structures::CapabilityData,
    };

    const NEW_MAX_TRIES: u32 = 10;
    const NEW_RECOVERY_TIME: u32 = 300;
    const NEW_LOCKOUT_RECOVERY: u32 = 300;

    fn read_dictionary_attack_parameters(context: &mut Context) -> (u32, u32, u32) {
        let (capability_data, _) = context
            .execute_without_session(|ctx| {
                ctx.get_capability(
                    CapabilityType::TpmProperties,
                    PropertyTag::MaxAuthFail.into(),
                    3,
                )
            })
            .expect("Failed to get dictionary attack parameters");
        let CapabilityData::TpmProperties(properties) = capability_data else {
            panic!("TPM returned an unexpected capability type");
        };

        let property_value = |property| {
            properties
                .find(property)
                .unwrap_or_else(|| panic!("TPM did not report {property:?}"))
                .value()
        };

        (
            property_value(PropertyTag::MaxAuthFail),
            property_value(PropertyTag::LockoutInterval),
            property_value(PropertyTag::LockoutRecovery),
        )
    }

    #[test]
    fn test_dictionary_attack_parameters() {
        let mut context = create_ctx_with_session();
        let original_parameters = read_dictionary_attack_parameters(&mut context);

        context
            .dictionary_attack_parameters(
                AuthHandle::Lockout,
                NEW_MAX_TRIES,
                NEW_RECOVERY_TIME,
                NEW_LOCKOUT_RECOVERY,
            )
            .expect("Failed to set dictionary attack parameters");
        assert_eq!(
            (NEW_MAX_TRIES, NEW_RECOVERY_TIME, NEW_LOCKOUT_RECOVERY),
            read_dictionary_attack_parameters(&mut context),
        );

        context
            .dictionary_attack_parameters(
                AuthHandle::Lockout,
                original_parameters.0,
                original_parameters.1,
                original_parameters.2,
            )
            .expect("Failed to restore dictionary attack parameters");
    }
}
