mod constant_object_handles {
    use std::convert::From;
    use tss_esapi::{
        handles::ObjectHandle,
        tss2_esys::{
            ESYS_TR, ESYS_TR_NONE, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL,
            ESYS_TR_RH_OWNER, ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV,
        },
    };

    #[test]
    fn test_constants_conversions() {
        // closure used for the repeated tests
        let conversion_check = |esys_handle: ESYS_TR, object_handle: ObjectHandle| {
            assert_eq!(esys_handle, ESYS_TR::from(object_handle));
            assert_eq!(object_handle, ObjectHandle::from(esys_handle));
        };

        // Check conversion of esys handles to TPM constants
        conversion_check(ESYS_TR_RH_OWNER, ObjectHandle::Owner);
        conversion_check(ESYS_TR_RH_NULL, ObjectHandle::Null);
        conversion_check(ESYS_TR_RH_LOCKOUT, ObjectHandle::Lockout);
        conversion_check(ESYS_TR_RH_ENDORSEMENT, ObjectHandle::Endorsement);
        conversion_check(ESYS_TR_RH_PLATFORM, ObjectHandle::Platform);
        conversion_check(ESYS_TR_RH_PLATFORM_NV, ObjectHandle::PlatformNv);
        conversion_check(ESYS_TR_NONE, ObjectHandle::None);
    }
}

mod test_pcr_handle {
    use std::convert::{From, TryFrom};
    use tss_esapi::{
        handles::{ObjectHandle, PcrHandle},
        tss2_esys::{
            ESYS_TR, ESYS_TR_PCR0, ESYS_TR_PCR1, ESYS_TR_PCR10, ESYS_TR_PCR11, ESYS_TR_PCR12,
            ESYS_TR_PCR13, ESYS_TR_PCR14, ESYS_TR_PCR15, ESYS_TR_PCR16, ESYS_TR_PCR17,
            ESYS_TR_PCR18, ESYS_TR_PCR19, ESYS_TR_PCR2, ESYS_TR_PCR20, ESYS_TR_PCR21,
            ESYS_TR_PCR22, ESYS_TR_PCR23, ESYS_TR_PCR24, ESYS_TR_PCR25, ESYS_TR_PCR26,
            ESYS_TR_PCR27, ESYS_TR_PCR28, ESYS_TR_PCR29, ESYS_TR_PCR3, ESYS_TR_PCR30,
            ESYS_TR_PCR31, ESYS_TR_PCR4, ESYS_TR_PCR5, ESYS_TR_PCR6, ESYS_TR_PCR7, ESYS_TR_PCR8,
            ESYS_TR_PCR9,
        },
    };

    #[test]
    fn test_conversion_of_invalid_handle() {
        let invalid_value: ESYS_TR = 0xFFFFFFFF;
        let invalid_object_handle: ObjectHandle = ObjectHandle::from(invalid_value);
        let _ = PcrHandle::try_from(invalid_value).unwrap_err();
        let _ = PcrHandle::try_from(invalid_object_handle).unwrap_err();
    }

    #[test]
    fn test_conversion_of_valid_handle() {
        // closure used for the repeated tests
        let conversion_check = |valid_esys_tr_value: ESYS_TR| {
            let valid_object_handle = ObjectHandle::try_from(valid_esys_tr_value).unwrap();

            // Conversion from ESYS_TR and ObjectHandle.
            let from_esys_tr = PcrHandle::try_from(valid_esys_tr_value).unwrap();
            let from_object_handle = PcrHandle::try_from(valid_esys_tr_value).unwrap();
            assert_eq!(from_esys_tr, from_object_handle);

            // Conversion into ObjectHandle
            let into_object_handle_1: ObjectHandle = from_esys_tr.into();
            let into_object_handle_2: ObjectHandle = from_object_handle.into();
            assert_eq!(valid_object_handle, into_object_handle_1);
            assert_eq!(valid_object_handle, into_object_handle_2);

            // Conversion into ESYS_TR
            let into_esys_tr_1: ESYS_TR = from_esys_tr.into();
            let into_esys_tr_2: ESYS_TR = from_object_handle.into();
            assert_eq!(valid_esys_tr_value, into_esys_tr_1);
            assert_eq!(valid_esys_tr_value, into_esys_tr_2);
        };

        // Check the valid values
        conversion_check(ESYS_TR_PCR0);
        conversion_check(ESYS_TR_PCR1);
        conversion_check(ESYS_TR_PCR2);
        conversion_check(ESYS_TR_PCR3);
        conversion_check(ESYS_TR_PCR4);
        conversion_check(ESYS_TR_PCR5);
        conversion_check(ESYS_TR_PCR6);
        conversion_check(ESYS_TR_PCR7);
        conversion_check(ESYS_TR_PCR8);
        conversion_check(ESYS_TR_PCR9);
        conversion_check(ESYS_TR_PCR10);
        conversion_check(ESYS_TR_PCR11);
        conversion_check(ESYS_TR_PCR12);
        conversion_check(ESYS_TR_PCR13);
        conversion_check(ESYS_TR_PCR14);
        conversion_check(ESYS_TR_PCR15);
        conversion_check(ESYS_TR_PCR16);
        conversion_check(ESYS_TR_PCR17);
        conversion_check(ESYS_TR_PCR18);
        conversion_check(ESYS_TR_PCR19);
        conversion_check(ESYS_TR_PCR20);
        conversion_check(ESYS_TR_PCR21);
        conversion_check(ESYS_TR_PCR22);
        conversion_check(ESYS_TR_PCR23);
        conversion_check(ESYS_TR_PCR24);
        conversion_check(ESYS_TR_PCR25);
        conversion_check(ESYS_TR_PCR26);
        conversion_check(ESYS_TR_PCR27);
        conversion_check(ESYS_TR_PCR28);
        conversion_check(ESYS_TR_PCR29);
        conversion_check(ESYS_TR_PCR30);
        conversion_check(ESYS_TR_PCR31);
    }
}

mod test_auth_handle {
    use tss_esapi::{
        handles::{AuthHandle, ObjectHandle},
        tss2_esys::{
            ESYS_TR, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_OWNER,
            ESYS_TR_RH_PLATFORM,
        },
    };

    #[test]
    fn test_constants_conversions() {
        let conversion_check =
            |esys_handle: ESYS_TR, object_handle: ObjectHandle, auth_handle: AuthHandle| {
                assert_eq!(esys_handle, ESYS_TR::from(auth_handle));
                assert_eq!(auth_handle, AuthHandle::from(esys_handle));
                assert_eq!(object_handle, ObjectHandle::from(auth_handle));
                assert_eq!(auth_handle, AuthHandle::from(object_handle));
            };

        // Check conversion of esys handles to TPM constants
        conversion_check(ESYS_TR_RH_OWNER, ObjectHandle::Owner, AuthHandle::Owner);
        conversion_check(
            ESYS_TR_RH_LOCKOUT,
            ObjectHandle::Lockout,
            AuthHandle::Lockout,
        );
        conversion_check(
            ESYS_TR_RH_ENDORSEMENT,
            ObjectHandle::Endorsement,
            AuthHandle::Endorsement,
        );
        conversion_check(
            ESYS_TR_RH_PLATFORM,
            ObjectHandle::Platform,
            AuthHandle::Platform,
        );
    }
}

mod test_session_handle {
    use std::convert::From;
    use tss_esapi::{
        handles::{ObjectHandle, SessionHandle},
        tss2_esys::{ESYS_TR, ESYS_TR_NONE, ESYS_TR_PASSWORD},
    };

    #[test]
    fn test_constants_conversions() {
        let conversion_check =
            |esys_handle: ESYS_TR, object_handle: ObjectHandle, session_handle: SessionHandle| {
                assert_eq!(esys_handle, ESYS_TR::from(session_handle));
                assert_eq!(session_handle, SessionHandle::from(esys_handle));
                assert_eq!(object_handle, ObjectHandle::from(session_handle));
                assert_eq!(session_handle, SessionHandle::from(object_handle));
            };

        conversion_check(
            ESYS_TR_PASSWORD,
            ObjectHandle::Password,
            SessionHandle::Password,
        );
        conversion_check(ESYS_TR_NONE, ObjectHandle::None, SessionHandle::None);
    }
}
