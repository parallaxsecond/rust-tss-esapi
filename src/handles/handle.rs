// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

///
/// Macro for generating a basic handle implementation
///
macro_rules! impl_basic_handle {
    (
        $(#[$outer:meta])*
        $handle_type:ident
    ) => {
        use crate::tss2_esys::ESYS_TR;
        use std::convert::From;

        $(#[$outer])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq)]
        pub struct $handle_type {
            value: u32,
        }

        impl $handle_type {
            pub fn value(&self) -> u32 {
                self.value
            }
        }

        impl From<ESYS_TR> for $handle_type {
            fn from(tss_esys_object_handle: ESYS_TR) -> $handle_type {
                $handle_type {
                    value: tss_esys_object_handle,
                }
            }
        }

        impl From<$handle_type> for ESYS_TR {
            fn from(handle: $handle_type) -> ESYS_TR {
                handle.value
            }
        }
    };
}

///
/// Macro for making a esys constant available
/// for a handle type.
///
macro_rules! add_constant_handle {
    ($handle_type:ident, $constant_handle_name:ident, $constant_handle_value:ident) => {
        impl $handle_type {
            #[allow(non_upper_case_globals)]
            pub const $constant_handle_name: $handle_type = $handle_type {
                value: $constant_handle_value,
            };
        }
    };
}

///
/// Object handle module
///
pub mod object {
    use crate::tss2_esys::{ESYS_TR_NONE, ESYS_TR_PASSWORD};
    impl_basic_handle!(
        /// General handle type.
        ObjectHandle
    );

    add_constant_handle!(ObjectHandle, PasswordHandle, ESYS_TR_PASSWORD);
    add_constant_handle!(ObjectHandle, NoneHandle, ESYS_TR_NONE);
}

///
/// Macro for creating ESYS_TR conversion for
/// constant handle types
///
macro_rules! impl_basic_multiple_constant_values_handle {
    ($constant_handle_type:ident) => {
        impl From<$constant_handle_type> for ESYS_TR {
            fn from(constant_handle: $constant_handle_type) -> ESYS_TR {
                // Cannot fail because each value is an ESYS_TR which is defined as u32.
                constant_handle.to_u32().unwrap()
            }
        }

        impl TryFrom<ESYS_TR> for $constant_handle_type {
            type Error = Error;
            fn try_from(tss_esys_handle: ESYS_TR) -> Result<$constant_handle_type> {
                $constant_handle_type::from_u32(tss_esys_handle).ok_or_else(|| {
                    error!(
                        "Error: failed to convert handle into {}",
                        std::stringify!($constant_handle_type)
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })
            }
        }
    };
}

///
/// Macro for creating handle conversion
/// from constant handle to a 'non-restricted'
/// handle type
///
macro_rules! impl_multiple_constant_values_handle_conversion {
    ($constant_handle_type:ident, $handle_type_other:ident) => {
        impl From<$constant_handle_type> for $handle_type_other {
            fn from(constant_handle: $constant_handle_type) -> $handle_type_other {
                // Cannot fail because each value is an ESYS_TR which is defined as u32.
                $handle_type_other::from(constant_handle.to_u32().unwrap())
            }
        }

        impl TryFrom<$handle_type_other> for $constant_handle_type {
            type Error = Error;
            fn try_from(other_handle: $handle_type_other) -> Result<$constant_handle_type> {
                $constant_handle_type::from_u32(other_handle.value()).ok_or_else(|| {
                    error!(
                        "Error: failed to convert handle into {}",
                        std::stringify!($constant_handle_type)
                    );
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })
            }
        }
    };
}

///
/// PCR handle module
///
pub mod pcr {
    use super::object::ObjectHandle;
    use crate::{
        tss2_esys::{
            ESYS_TR, ESYS_TR_PCR0, ESYS_TR_PCR1, ESYS_TR_PCR10, ESYS_TR_PCR11, ESYS_TR_PCR12,
            ESYS_TR_PCR13, ESYS_TR_PCR14, ESYS_TR_PCR15, ESYS_TR_PCR16, ESYS_TR_PCR17,
            ESYS_TR_PCR18, ESYS_TR_PCR19, ESYS_TR_PCR2, ESYS_TR_PCR20, ESYS_TR_PCR21,
            ESYS_TR_PCR22, ESYS_TR_PCR23, ESYS_TR_PCR24, ESYS_TR_PCR25, ESYS_TR_PCR26,
            ESYS_TR_PCR27, ESYS_TR_PCR28, ESYS_TR_PCR29, ESYS_TR_PCR3, ESYS_TR_PCR30,
            ESYS_TR_PCR31, ESYS_TR_PCR4, ESYS_TR_PCR5, ESYS_TR_PCR6, ESYS_TR_PCR7, ESYS_TR_PCR8,
            ESYS_TR_PCR9,
        },
        Error, Result, WrapperErrorKind,
    };

    use log::error;
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::convert::{From, TryFrom};
    /// PCR handle
    ///
    /// Handles to the pre-allocated
    /// PCR meta data objects.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u32)]
    pub enum PcrHandle {
        Pcr0 = ESYS_TR_PCR0,
        Pcr1 = ESYS_TR_PCR1,
        Pcr2 = ESYS_TR_PCR2,
        Pcr3 = ESYS_TR_PCR3,
        Pcr4 = ESYS_TR_PCR4,
        Pcr5 = ESYS_TR_PCR5,
        Pcr6 = ESYS_TR_PCR6,
        Pcr7 = ESYS_TR_PCR7,
        Pcr8 = ESYS_TR_PCR8,
        Pcr9 = ESYS_TR_PCR9,
        Pcr10 = ESYS_TR_PCR10,
        Pcr11 = ESYS_TR_PCR11,
        Pcr12 = ESYS_TR_PCR12,
        Pcr13 = ESYS_TR_PCR13,
        Pcr14 = ESYS_TR_PCR14,
        Pcr15 = ESYS_TR_PCR15,
        Pcr16 = ESYS_TR_PCR16,
        Pcr17 = ESYS_TR_PCR17,
        Pcr18 = ESYS_TR_PCR18,
        Pcr19 = ESYS_TR_PCR19,
        Pcr20 = ESYS_TR_PCR20,
        Pcr21 = ESYS_TR_PCR21,
        Pcr22 = ESYS_TR_PCR22,
        Pcr23 = ESYS_TR_PCR23,
        Pcr24 = ESYS_TR_PCR24,
        Pcr25 = ESYS_TR_PCR25,
        Pcr26 = ESYS_TR_PCR26,
        Pcr27 = ESYS_TR_PCR27,
        Pcr28 = ESYS_TR_PCR28,
        Pcr29 = ESYS_TR_PCR29,
        Pcr30 = ESYS_TR_PCR30,
        Pcr31 = ESYS_TR_PCR31,
    }

    impl_basic_multiple_constant_values_handle!(PcrHandle);
    impl_multiple_constant_values_handle_conversion!(PcrHandle, ObjectHandle);
}

///
/// TPM Constants handle module
///
pub mod tpm_constants {
    use super::object::ObjectHandle;
    use crate::{
        tss2_esys::{
            ESYS_TR, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_LOCKOUT, ESYS_TR_RH_NULL, ESYS_TR_RH_OWNER,
            ESYS_TR_RH_PLATFORM, ESYS_TR_RH_PLATFORM_NV,
        },
        Error, Result, WrapperErrorKind,
    };
    use log::error;
    use num_derive::{FromPrimitive, ToPrimitive};
    use num_traits::{FromPrimitive, ToPrimitive};
    use std::convert::{From, TryFrom};
    /// TpmConstants Handle
    ///
    /// Represents an esys handle for
    /// tpm constant resource handles.
    #[derive(FromPrimitive, ToPrimitive, Debug, Copy, Clone, PartialEq, Eq)]
    #[repr(u32)]
    pub enum TpmConstantsHandle {
        Owner = ESYS_TR_RH_OWNER,
        Null = ESYS_TR_RH_NULL,
        Lockout = ESYS_TR_RH_LOCKOUT,
        Endorsement = ESYS_TR_RH_ENDORSEMENT,
        Platform = ESYS_TR_RH_PLATFORM,
        PlatformNv = ESYS_TR_RH_PLATFORM_NV,
        // ESYS_TR_RH_AUTH ....?
    }

    impl_basic_multiple_constant_values_handle!(TpmConstantsHandle);
    impl_multiple_constant_values_handle_conversion!(TpmConstantsHandle, ObjectHandle);
}

///
/// Macro for implmeneting conversion between handles.
///
macro_rules! impl_handle_conversion {
    ($handle_type_self:ident, $handle_type_other:ident) => {
        impl From<$handle_type_self> for $handle_type_other {
            fn from(handle_self: $handle_type_self) -> $handle_type_other {
                $handle_type_other::from(ESYS_TR::from(handle_self.value))
            }
        }

        impl From<$handle_type_other> for $handle_type_self {
            fn from(handle_other: $handle_type_other) -> $handle_type_self {
                $handle_type_self {
                    value: handle_other.value(),
                }
            }
        }
    };
}

///
/// Auth handle module
///
pub mod auth {
    use super::object::ObjectHandle;
    impl_basic_handle!(
        /// Auth handle
        ///
        /// Represents an esys handle to resources
        /// that can be used for authentication.
        AuthHandle
    );
    impl_handle_conversion!(AuthHandle, ObjectHandle);
}

///
/// NV Index handle module
///
pub mod nv_index {
    use super::auth::AuthHandle;
    use super::object::ObjectHandle;
    impl_basic_handle!(
        /// NV Index Handle
        ///
        /// Represents an esys resource handle
        /// for a nv index.
        NvIndexHandle
    );
    impl_handle_conversion!(NvIndexHandle, ObjectHandle);
    impl_handle_conversion!(NvIndexHandle, AuthHandle);
}

/// Key handle module
pub mod key {
    use super::object::ObjectHandle;
    impl_basic_handle!(
        /// Key Handle
        ///
        /// Represents an esys resource handle
        /// for a key.
        KeyHandle
    );
    impl_handle_conversion!(KeyHandle, ObjectHandle);
}

///
/// Session handle module
///
pub mod session {
    use super::auth::AuthHandle;
    use super::object::ObjectHandle;
    use crate::tss2_esys::ESYS_TR_PASSWORD;
    impl_basic_handle!(
        /// Session Handle
        ///
        /// Represents an esys handle used for
        /// referencing session resources.
        SessionHandle
    );
    impl_handle_conversion!(SessionHandle, ObjectHandle);
    impl_handle_conversion!(SessionHandle, AuthHandle);
    add_constant_handle!(SessionHandle, PasswordHandle, ESYS_TR_PASSWORD);
}
