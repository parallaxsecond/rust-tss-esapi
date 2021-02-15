// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::constants::CapabilityType;

mod common;
use common::create_ctx_without_session;

mod test_capabs {
    use super::*;

    #[test]
    fn test_algorithms() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::Algorithms, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_handles() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::Handles, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_command() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::Command, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_pp_commands() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::PPCommands, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_audit_commands() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::AuditCommands, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_assigned_pcr() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::AssignedPCR, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_tpm_properties() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::TPMProperties, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_pcr_properties() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::PCRProperties, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_ecc_curves() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capability(CapabilityType::ECCCurves, 0, 80)
            .unwrap();
    }
}
