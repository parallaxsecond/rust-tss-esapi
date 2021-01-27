// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::constants::types::capability::CapabilityType;

mod common;
use common::create_ctx_without_session;

mod test_capabs {
    use super::*;

    #[test]
    fn test_algorithms() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::Algorithms, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_handles() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::Handles, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_command() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::Command, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_pp_commands() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::PPCommands, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_audit_commands() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::AuditCommands, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_assigned_pcr() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::AssignedPCR, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_tpm_properties() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::TPMProperties, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_pcr_properties() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::PCRProperties, 0, 80)
            .unwrap();
    }

    #[test]
    fn test_ecc_curves() {
        let mut context = create_ctx_without_session();

        let (_capabs, _more) = context
            .get_capabilities(CapabilityType::ECCCurves, 0, 80)
            .unwrap();
    }
}
