// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::TryFrom;
use tss_esapi::{
    constants::tss::{TPM2_RH_ENDORSEMENT, TPM2_RH_NULL, TPM2_RH_OWNER, TPM2_RH_PLATFORM},
    handles::{AuthHandle, NvIndexHandle, TpmConstantsHandle},
    interface_types::resource_handles::{
        Clear, Endorsement, Hierarchy, HierarchyAuth, Lockout, NvAuth, Owner, Platform, Provision,
    },
    tss2_esys::{
        ESYS_TR, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_NULL, ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM,
        TPM2_RH,
    },
};

mod test_hierarchy {
    use super::*;
    #[test]
    fn test_conversions() {
        let test_conversion =
            |hierarchy: Hierarchy, tpm_rh: TPM2_RH, esys_rh: ESYS_TR, name: &str| {
                assert_eq!(hierarchy.esys_rh(), esys_rh);
                assert_eq!(hierarchy.rh(), tpm_rh);
                let from_esys_rh = Hierarchy::try_from(esys_rh).unwrap_or_else(|_| {
                    panic!(format!(
                        "Failed to create Hierarchy from ESYS_TR_RH={}",
                        name
                    ))
                });
                assert_eq!(from_esys_rh, hierarchy);
                assert_eq!(from_esys_rh.esys_rh(), esys_rh);
                assert_eq!(from_esys_rh.rh(), tpm_rh);
                let from_tpm_rh = Hierarchy::try_from(tpm_rh).unwrap_or_else(|_| {
                    panic!(format!("Failed to create Hierarchy from TPM2_RH={}", name))
                });
                assert_eq!(from_tpm_rh, hierarchy);
                assert_eq!(from_tpm_rh.esys_rh(), esys_rh);
                assert_eq!(from_tpm_rh.rh(), tpm_rh);
            };

        test_conversion(Hierarchy::Owner, TPM2_RH_OWNER, ESYS_TR_RH_OWNER, "OWNER");
        test_conversion(
            Hierarchy::Platform,
            TPM2_RH_PLATFORM,
            ESYS_TR_RH_PLATFORM,
            "PLATFORM",
        );
        test_conversion(
            Hierarchy::Endorsement,
            TPM2_RH_ENDORSEMENT,
            ESYS_TR_RH_ENDORSEMENT,
            "ENDORSEMENT",
        );
        test_conversion(Hierarchy::Null, TPM2_RH_NULL, ESYS_TR_RH_NULL, "NULL");
    }
}

mod test_hierarchy_auth {
    use super::*;
    #[test]
    fn test_conversions() {
        let test_conversion =
            |hierarchy_auth: HierarchyAuth, tpm_rh: TPM2_RH, esys_rh: ESYS_TR, name: &str| {
                assert_eq!(hierarchy_auth.esys_rh(), esys_rh);
                assert_eq!(hierarchy_auth.rh(), tpm_rh);
                let from_esys_rh = HierarchyAuth::try_from(esys_rh).unwrap_or_else(|_| {
                    panic!(format!(
                        "Failed to create HierarchyAuth from ESYS_TR_RH={}",
                        name
                    ))
                });
                assert_eq!(from_esys_rh, hierarchy_auth);
                assert_eq!(from_esys_rh.esys_rh(), esys_rh);
                assert_eq!(from_esys_rh.rh(), tpm_rh);
                let from_tpm_rh = HierarchyAuth::try_from(tpm_rh).unwrap_or_else(|_| {
                    panic!(format!(
                        "Failed to create HierarchyAuth from TPM2_RH={}",
                        name
                    ))
                });
                assert_eq!(from_tpm_rh, hierarchy_auth);
                assert_eq!(from_tpm_rh.esys_rh(), esys_rh);
                assert_eq!(from_tpm_rh.rh(), tpm_rh);
            };

        test_conversion(
            HierarchyAuth::Owner,
            TPM2_RH_OWNER,
            ESYS_TR_RH_OWNER,
            "OWNER",
        );
        test_conversion(
            HierarchyAuth::Platform,
            TPM2_RH_PLATFORM,
            ESYS_TR_RH_PLATFORM,
            "PLATFORM",
        );
        test_conversion(
            HierarchyAuth::Endorsement,
            TPM2_RH_ENDORSEMENT,
            ESYS_TR_RH_ENDORSEMENT,
            "ENDORSEMENT",
        );
    }
}

mod test_platform {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(
            AuthHandle::from(Platform::Platform),
            AuthHandle::PlatformHandle
        );
        assert_eq!(
            Platform::try_from(AuthHandle::PlatformHandle)
                .expect("Failed to convert AuthHandle into Platform"),
            Platform::Platform
        );
    }
}

mod test_owner {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(
            TpmConstantsHandle::from(Owner::Owner),
            TpmConstantsHandle::Owner
        );
        assert_eq!(
            TpmConstantsHandle::from(Owner::Null),
            TpmConstantsHandle::Null
        );
        assert_eq!(
            Owner::try_from(TpmConstantsHandle::Owner)
                .expect("Failed to convert TpmConstantHandle into Owner"),
            Owner::Owner
        );
        assert_eq!(
            Owner::try_from(TpmConstantsHandle::Null)
                .expect("Failed to convert TpmConstantHandle into Owner"),
            Owner::Null
        );
    }
}

mod test_endorsement {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(
            TpmConstantsHandle::from(Endorsement::Endorsement),
            TpmConstantsHandle::Endorsement
        );
        assert_eq!(
            TpmConstantsHandle::from(Endorsement::Null),
            TpmConstantsHandle::Null
        );
        assert_eq!(
            Endorsement::try_from(TpmConstantsHandle::Endorsement)
                .expect("Failed to convert TpmConstantHandle into Endorsement"),
            Endorsement::Endorsement
        );
        assert_eq!(
            Endorsement::try_from(TpmConstantsHandle::Null)
                .expect("Failed to convert TpmConstantHandle into Endorsement"),
            Endorsement::Null
        );
    }
}

mod test_provision {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(Provision::Owner), AuthHandle::OwnerHandle);
        assert_eq!(
            AuthHandle::from(Provision::Platform),
            AuthHandle::PlatformHandle
        );
        assert_eq!(
            Provision::try_from(AuthHandle::OwnerHandle)
                .expect("Failed to convert AuthHandle into Provision"),
            Provision::Owner
        );
        assert_eq!(
            Provision::try_from(AuthHandle::PlatformHandle)
                .expect("Failed to convert AuthHandle into Provision"),
            Provision::Platform
        );
    }
}

mod test_clear {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(AuthHandle::from(Clear::Owner), AuthHandle::OwnerHandle);
        assert_eq!(
            AuthHandle::from(Clear::Platform),
            AuthHandle::PlatformHandle
        );
        assert_eq!(
            Clear::try_from(AuthHandle::OwnerHandle)
                .expect("Failed to convert AuthHandle into Clear"),
            Clear::Owner
        );
        assert_eq!(
            Clear::try_from(AuthHandle::PlatformHandle)
                .expect("Failed to convert AuthHandle into Provision"),
            Clear::Platform
        );
    }
}

mod test_nv_auth {
    use super::*;

    #[test]
    fn test_conversions() {
        assert_eq!(
            AuthHandle::from(NvAuth::Platform),
            AuthHandle::PlatformHandle
        );
        assert_eq!(AuthHandle::from(NvAuth::Owner), AuthHandle::OwnerHandle);

        let esys_handle: ESYS_TR = 0x12345678;
        let nv_index_handle = NvIndexHandle::from(esys_handle);
        assert_eq!(
            AuthHandle::from(NvAuth::NvIndex(nv_index_handle)),
            AuthHandle::from(esys_handle)
        );

        assert_eq!(
            NvAuth::try_from(AuthHandle::PlatformHandle)
                .expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::Platform
        );
        assert_eq!(
            NvAuth::try_from(AuthHandle::OwnerHandle)
                .expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::Owner
        );
        assert_eq!(
            NvAuth::try_from(AuthHandle::from(esys_handle))
                .expect("Failed to convert AuthHandle into NvAuth"),
            NvAuth::NvIndex(nv_index_handle)
        );
    }
}

mod test_lockout {
    use super::*;
    #[test]
    fn test_conversions() {
        assert_eq!(
            TpmConstantsHandle::from(Lockout::Lockout),
            TpmConstantsHandle::Lockout
        );
        assert_eq!(
            Lockout::try_from(TpmConstantsHandle::Lockout)
                .expect("Failed to convert TpmConstantHandle into Lockout"),
            Lockout::Lockout
        );
    }
}
