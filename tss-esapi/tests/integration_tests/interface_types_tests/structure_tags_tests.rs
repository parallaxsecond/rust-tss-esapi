// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

macro_rules! test_valid_conversions {
    (AttestationType::$attestation_type_item:ident, StructureTag::$strucutre_tag_item:ident) => {
        assert_eq!(
            AttestationType::$attestation_type_item,
            AttestationType::try_from(StructureTag::$strucutre_tag_item).expect(&format!(
                "Could not convert StructureTag {}",
                stringify!($attestation_type_item)
            )),
            "StructureTag {} did not convert to the correct AttestationType {}",
            stringify!($strucutre_tag_item),
            stringify!($attestation_type_item),
        );

        assert_eq!(
            StructureTag::$strucutre_tag_item,
            StructureTag::from(AttestationType::$attestation_type_item),
            "AttestationType {} did not convert to the correct StructureTag {}",
            stringify!($attestation_type_item),
            stringify!($strucutre_tag_item),
        );
    };

    (CommandTag::$attestation_type_item:ident, StructureTag::$strucutre_tag_item:ident) => {
        assert_eq!(
            CommandTag::$attestation_type_item,
            CommandTag::try_from(StructureTag::$strucutre_tag_item).expect(&format!(
                "Could not convert StructureTag {}",
                stringify!($attestation_type_item)
            )),
            "StructureTag {} did not convert to the correct CommandTag {}",
            stringify!($strucutre_tag_item),
            stringify!($attestation_type_item),
        );

        assert_eq!(
            StructureTag::$strucutre_tag_item,
            StructureTag::from(CommandTag::$attestation_type_item),
            "CommandTag {} did not convert to the correct StructureTag {}",
            stringify!($attestation_type_item),
            stringify!($strucutre_tag_item),
        );
    };
}

mod attestation_type_tests {
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::StructureTag, interface_types::structure_tags::AttestationType, Error,
        WrapperErrorKind,
    };

    #[test]
    fn test_conversions() {
        test_valid_conversions!(AttestationType::Certify, StructureTag::AttestCertify);
        test_valid_conversions!(AttestationType::Quote, StructureTag::AttestQuote);
        test_valid_conversions!(
            AttestationType::SessionAudit,
            StructureTag::AttestSessionAudit
        );
        test_valid_conversions!(
            AttestationType::CommandAudit,
            StructureTag::AttestCommandAudit
        );
        test_valid_conversions!(AttestationType::Time, StructureTag::AttestTime);
        test_valid_conversions!(AttestationType::Creation, StructureTag::AttestCreation);
        test_valid_conversions!(AttestationType::Nv, StructureTag::AttestNv);
        test_valid_conversions!(AttestationType::NvDigest, StructureTag::AttestNvDigest);
    }

    #[test]
    fn test_invalid_conversions() {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            AttestationType::try_from(StructureTag::FuManifest),
            "Expected an error when converting StructureTag FuManifest into AttestationType",
        )
    }

    #[test]
    fn test_marshall_unmarshall() {
        let val = AttestationType::SessionAudit;
        crate::common::check_marshall_unmarshall(&val);
        crate::common::check_marshall_unmarshall_offset(&val);
    }
}

mod command_tag_tests {
    use std::convert::TryFrom;
    use tss_esapi::{
        constants::StructureTag, interface_types::structure_tags::CommandTag, Error,
        WrapperErrorKind,
    };

    #[test]
    fn test_conversions() {
        test_valid_conversions!(CommandTag::Sessions, StructureTag::Sessions);
        test_valid_conversions!(CommandTag::NoSessions, StructureTag::NoSessions);
    }

    #[test]
    fn test_invalid_conversions() {
        assert_eq!(
            Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
            CommandTag::try_from(StructureTag::FuManifest),
            "Expected an error when converting StructureTag FuManifest into CommandTag",
        )
    }

    #[test]
    fn test_marshall_unmarshall() {
        let val = CommandTag::Sessions;
        crate::common::check_marshall_unmarshall(&val);
        crate::common::check_marshall_unmarshall_offset(&val);
    }
}
