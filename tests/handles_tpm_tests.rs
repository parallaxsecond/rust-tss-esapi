// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use std::convert::{Into, TryFrom};
use tss_esapi::{
    constants::tss::{
        TPM2_HT_AC, TPM2_HT_HMAC_SESSION, TPM2_HT_LOADED_SESSION, TPM2_HT_NV_INDEX, TPM2_HT_PCR,
        TPM2_HT_PERMANENT, TPM2_HT_PERSISTENT, TPM2_HT_POLICY_SESSION, TPM2_HT_SAVED_SESSION,
        TPM2_HT_TRANSIENT,
    },
    handles::tpm::{
        AcTpmHandle, HmacSessionTpmHandle, LoadedSessionTpmHandle, NvIndexTpmHandle, PcrTpmHandle,
        PermanentTpmHandle, PersistentTpmHandle, PolicySessionTpmHandle, SavedSessionTpmHandle,
        TpmHandle, TransientTpmHandle,
    },
    tss2_esys::TPM2_HANDLE,
};

mod test_tpm_handles {
    use super::*;

    #[test]
    fn test_pcr_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = PcrTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_PCR;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = PcrTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_nv_index_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = NvIndexTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_NV_INDEX;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = NvIndexTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_hmac_session_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = HmacSessionTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_HMAC_SESSION;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = HmacSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_loaded_session_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = LoadedSessionTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_LOADED_SESSION;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = LoadedSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_policy_session_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = PolicySessionTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_POLICY_SESSION;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = PolicySessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_saved_session_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = SavedSessionTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_SAVED_SESSION;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = SavedSessionTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_permanent_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = PermanentTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_PERMANENT;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = PermanentTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_transient_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = TransientTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_TRANSIENT;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = TransientTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_persistent_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = PersistentTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_PERSISTENT;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = PersistentTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_ac_tpm_handle() {
        let invalid_value: u32 = 0xFFFFFFFF;
        let _ = AcTpmHandle::new(invalid_value).unwrap_err();
        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_AC;
        let valid_value: u32 = u32::from_be_bytes(be_bytes);
        let _ = AcTpmHandle::new(valid_value).unwrap();
    }

    #[test]
    fn test_general_tpm_handle_from_tss_tpm_handle_conversion() {
        let invalid_value: TPM2_HANDLE = 0xFFFFFFFF;
        let _ = TpmHandle::try_from(invalid_value).unwrap_err();

        let mut be_bytes = invalid_value.to_be_bytes();
        be_bytes[0] = TPM2_HT_PCR;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::Pcr(PcrTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );

        be_bytes[0] = TPM2_HT_NV_INDEX;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::NvIndex(NvIndexTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );

        be_bytes[0] = TPM2_HT_HMAC_SESSION;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::HmacSession(
                HmacSessionTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap()
            )
        );

        // TPM2_HT_LOADED_SESSION is the same as TPM2_HT_HMAC_SESSION

        be_bytes[0] = TPM2_HT_POLICY_SESSION;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::PolicySession(
                PolicySessionTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap()
            )
        );

        // TPM2_HT_SAVED_SESSION is the same as TPM2_HT_POLICY_SESSION

        be_bytes[0] = TPM2_HT_PERMANENT;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::Permanent(PermanentTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );

        be_bytes[0] = TPM2_HT_TRANSIENT;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::Transient(TransientTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );

        be_bytes[0] = TPM2_HT_PERSISTENT;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::Persistent(PersistentTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );

        be_bytes[0] = TPM2_HT_AC;

        assert_eq!(
            TpmHandle::try_from(u32::from_be_bytes(be_bytes)).unwrap(),
            TpmHandle::Ac(AcTpmHandle::new(u32::from_be_bytes(be_bytes)).unwrap())
        );
    }

    #[test]
    fn test_general_tpm_handle_to_tss_tpm_handle_conversion() {
        {
            let expected = u32::from_be_bytes([TPM2_HT_PCR, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Pcr(PcrTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_NV_INDEX, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::NvIndex(NvIndexTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_HMAC_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::HmacSession(HmacSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_LOADED_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle =
                TpmHandle::LoadedSession(LoadedSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_POLICY_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle =
                TpmHandle::PolicySession(PolicySessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_SAVED_SESSION, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::SavedSession(SavedSessionTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_PERMANENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Permanent(PermanentTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_TRANSIENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Transient(TransientTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_PERSISTENT, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Persistent(PersistentTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }

        {
            let expected = u32::from_be_bytes([TPM2_HT_AC, 0x00, 0x00, 0x01]);
            let tpm_handle = TpmHandle::Ac(AcTpmHandle::new(expected).unwrap());
            let actual: TPM2_HANDLE = tpm_handle.into();
            assert_eq!(expected, actual);
        }
    }
}
