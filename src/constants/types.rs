use crate::{Error, Result, WrapperErrorKind};
use log::error;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::convert::{From, TryFrom};

/// Startup module
pub mod startup {
    use super::*;
    use crate::{
        constants::tss::{TPM2_SU_CLEAR, TPM2_SU_STATE},
        tss2_esys::TPM2_SU,
    };

    /// Enum repsenting the diffrent TPM Startup Type values.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u16)]
    pub enum StartupType {
        Clear = TPM2_SU_CLEAR,
        State = TPM2_SU_STATE,
    }

    impl From<StartupType> for TPM2_SU {
        fn from(startup_type: StartupType) -> TPM2_SU {
            // The values are well defined so this cannot fail.
            startup_type.to_u16().unwrap()
        }
    }

    impl TryFrom<TPM2_SU> for StartupType {
        type Error = Error;
        fn try_from(tpm_startup_type: TPM2_SU) -> Result<StartupType> {
            StartupType::from_u16(tpm_startup_type).ok_or_else(|| {
                error!(
                    "Error: value = {} did not match any StartupType.",
                    tpm_startup_type
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })
        }
    }
}

/// Session module
pub mod session {
    use super::*;
    use crate::{
        constants::tss::{TPM2_SE_HMAC, TPM2_SE_POLICY, TPM2_SE_TRIAL},
        tss2_esys::TPM2_SE,
    };

    /// Enum representing the different TPM session types.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u8)]
    pub enum SessionType {
        Hmac = TPM2_SE_HMAC,
        Policy = TPM2_SE_POLICY,
        Trial = TPM2_SE_TRIAL,
    }

    impl From<SessionType> for TPM2_SE {
        fn from(session_type: SessionType) -> TPM2_SE {
            // The values are well defined so this cannot fail.
            session_type.to_u8().unwrap()
        }
    }

    impl TryFrom<TPM2_SE> for SessionType {
        type Error = Error;
        fn try_from(tpm_session_type: TPM2_SE) -> Result<SessionType> {
            SessionType::from_u8(tpm_session_type).ok_or_else(|| {
                error!(
                    "Error: value = {} did not match any SessionType.",
                    tpm_session_type
                );
                Error::local_error(WrapperErrorKind::InvalidParam)
            })
        }
    }
}
