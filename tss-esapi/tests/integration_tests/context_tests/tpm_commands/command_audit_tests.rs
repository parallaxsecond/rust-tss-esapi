// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_set_command_code_audit_status {
    use crate::common::create_ctx_with_session;
    use std::convert::TryFrom;
    use tss_esapi::{
        Context,
        constants::{CapabilityType, CommandCode},
        handles::AuthHandle,
        interface_types::{algorithm::HashingAlgorithm, session_handles::AuthSession},
        structures::{CapabilityData, CommandCodeList},
    };

    fn set_command_audit_status(
        context: &mut Context,
        set_list: CommandCodeList,
        clear_list: CommandCodeList,
    ) {
        context
            .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
                ctx.set_command_code_audit_status(
                    AuthHandle::Owner,
                    HashingAlgorithm::Null,
                    set_list,
                    clear_list,
                )
            })
            .expect("Failed to set command code audit status");
    }

    fn audit_commands(context: &mut Context) -> CommandCodeList {
        let (capability_data, _more_data) = context
            .execute_without_session(|ctx| {
                ctx.get_capability(
                    CapabilityType::AuditCommands,
                    0,
                    CommandCodeList::MAX_SIZE as u32,
                )
            })
            .expect("Failed to get audit commands capability");

        match capability_data {
            CapabilityData::AuditCommands(command_codes) => command_codes,
            _ => panic!("Unexpected capability data returned for audit commands"),
        }
    }

    #[test]
    fn test_set_command_code_audit_status() {
        let mut context = create_ctx_with_session();
        let command_code = CommandCode::GetRandom;

        set_command_audit_status(
            &mut context,
            CommandCodeList::new(),
            CommandCodeList::try_from(vec![command_code]).unwrap(),
        );
        assert!(!audit_commands(&mut context).contains(&command_code));

        set_command_audit_status(
            &mut context,
            CommandCodeList::try_from(vec![command_code]).unwrap(),
            CommandCodeList::new(),
        );
        assert!(audit_commands(&mut context).contains(&command_code));

        set_command_audit_status(
            &mut context,
            CommandCodeList::new(),
            CommandCodeList::try_from(vec![command_code]).unwrap(),
        );
        assert!(!audit_commands(&mut context).contains(&command_code));
    }
}
