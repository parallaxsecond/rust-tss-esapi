// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{tss2_esys::UINT32, Result};
use std::convert::TryFrom;

/// Trait for types that can be converted into
/// TPM marshalled data.
pub trait Marshall: Sized {
    const BUFFER_SIZE: usize;
    /// Returns the type in the form of marshalled data
    fn marshall(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; Self::BUFFER_SIZE];
        let mut offset = 0;

        self.marshall_offset(&mut buffer, &mut offset)?;

        buffer.truncate(offset);

        Ok(buffer)
    }

    /// Writes the type in the form of marshalled data to `marshalled_data`,
    /// and modifies the `offset` to point to the first byte in the buffer
    /// which was not written in the conversion.
    fn marshall_offset(&self, _marshalled_data: &mut [u8], _offset: &mut usize) -> Result<()> {
        unimplemented!();
    }
}

/// Trait for types that can be created from
/// TPM marshalled data.
pub trait UnMarshall: Sized {
    /// Creates the type from marshalled data.
    fn unmarshall(marshalled_data: &[u8]) -> Result<Self> {
        Self::unmarshall_offset(marshalled_data, &mut 0)
    }

    /// Creates the type from the marshalled data, and modifies
    /// the `offset` to point to the first byte in the `marshalled_data`
    /// buffer which was not used in the conversion.
    fn unmarshall_offset(_marshalled_data: &[u8], _offset: &mut usize) -> Result<Self> {
        unimplemented!();
    }
}

/// A macro for implementing the Marshall trait
/// for a specific TSS type.
macro_rules! impl_marshall_trait {
    ($native_type:ident, $tss_type:ident, $tss_mu_type:ident, $convert_expression:stmt, $( $ref_sign:tt )?) => {
        paste::item! {
            impl $crate::traits::Marshall for $native_type {
                const BUFFER_SIZE: usize = ::std::mem::size_of::<$tss_type>();

                fn marshall_offset(
                    &self,
                    marshalled_data: &mut [u8],
                    offset: &mut usize,
                ) -> $crate::Result<()> {
                    let ffi_object = self.clone().$convert_expression;
                    let ffi_buffer_size = $crate::ffi::FfiSizeType::try_from(marshalled_data.len())?;
                    let mut ffi_offset = $crate::ffi::FfiSizeType::try_from(*offset)?;
                    $crate::ReturnCode::ensure_success(
                        unsafe {
                            $crate::tss2_esys::[< Tss2_MU_ $tss_mu_type _Marshal >](
                                $( $ref_sign )?ffi_object,
                                marshalled_data.as_mut_ptr(),
                                ffi_buffer_size.into(),
                                ffi_offset.as_mut_ptr(),
                            )
                        },
                        |ret| {
                            log::error!(
                                "Failed to marshall {}: {}",
                                std::stringify!($native_type),
                                ret
                            );
                        },
                    )?;
                    *offset = usize::try_from(ffi_offset)?;
                    Ok(())
                }
            }
        }
    };
}

/// A macro for implementing the Unmarshall trait
/// for a specific TSS type.
macro_rules! impl_unmarshall_trait {
    ($native_type:ident, $tss_type:ident, $tss_mu_type:ident, $convert_expression:expr) => {
        paste::item! {
            impl $crate::traits::UnMarshall for $native_type {
                fn unmarshall_offset(marshalled_data: &[u8], offset: &mut usize) -> Result<Self> {
                    let mut dest = $tss_type::default();
                    let ffi_buffer_size = $crate::ffi::FfiSizeType::try_from(marshalled_data.len())?;
                    let mut ffi_offset = $crate::ffi::FfiSizeType::try_from(*offset)?;
                    crate::ReturnCode::ensure_success(
                        unsafe {
                            crate::tss2_esys::[ < Tss2_MU_ $tss_mu_type _Unmarshal >](
                                marshalled_data.as_ptr(),
                                ffi_buffer_size.into(),
                                ffi_offset.as_mut_ptr(),
                                &mut dest,
                            )
                        },
                        |ret| log::error!("Failed to unmarshal {}: {}", std::stringify!($native_type), ret),
                    )?;
                    *offset = usize::try_from(ffi_offset)?;
                    $convert_expression(dest)
                }
            }
        }
    };
}

/// Macro used to implement Marshall and Unmarshall for types
/// that are just a type aliases of native types and are passed
/// to MUAPI by value.
macro_rules! impl_mu_aliases {
    ($tss_type:ident) => {
        $crate::traits::impl_marshall_trait!($tss_type, $tss_type, $tss_type, into(),);
        $crate::traits::impl_unmarshall_trait!($tss_type, $tss_type, $tss_type, Ok);
    };
}

/// Macro used to implement Marshall and Unmarshall for types that
/// can be converted from native to TSS i.e. it cannot fail and are
/// passed to MUAPI by value.
macro_rules! impl_mu_simple {
    ($native_type:ident, $tss_type:ident, $tss_mu_type:ident) => {
        $crate::traits::impl_marshall_trait!($native_type, $tss_type, $tss_mu_type, into(),);
        $crate::traits::impl_unmarshall_trait!(
            $native_type,
            $tss_type,
            $tss_mu_type,
            $native_type::try_from
        );
    };
    ($native_type:ident, $tss_type:ident) => {
        $crate::traits::impl_mu_simple!($native_type, $tss_type, $tss_type);
    };
}

/// Macro used to implement Marshall and Unmarshall for types that
/// can be converted from native to TSS without failing and are
/// passed to MUAPI by reference(i.e. pointer).
macro_rules! impl_mu_standard {
    ($native_type:ident, $tss_type:ident, $tss_mu_type:ident) => {
        $crate::traits::impl_marshall_trait!($native_type, $tss_type, $tss_mu_type, into(), &);
        $crate::traits::impl_unmarshall_trait!(
            $native_type,
            $tss_type,
            $tss_mu_type,
            $native_type::try_from
        );
    };
    ($native_type:ident, $tss_type:ident) => {
        $crate::traits::impl_mu_standard!($native_type, $tss_type, $tss_type);
    };
}

/// Macro used to implement Marshall and Unmarshall for types that
/// can be converted from native to TSS with the possibility of failing
/// and are passed to MUAPI by reference(i.e. pointer).
macro_rules! impl_mu_complex {
    ($native_type:ident, $tss_type:ident, $tss_mu_type:ident) => {
        $crate::traits::impl_marshall_trait!($native_type, $tss_type, $tss_mu_type, try_into()?, &);
        $crate::traits::impl_unmarshall_trait!(
            $native_type,
            $tss_type,
            $tss_mu_type,
            $native_type::try_from
        );
    };
    ($native_type:ident, $tss_type:ident) => {
        $crate::traits::impl_mu_complex!($native_type, $tss_type, $tss_type);
    };
}

// Make the macros usable outside of the module.
pub(crate) use impl_marshall_trait;
pub(crate) use impl_mu_aliases;
pub(crate) use impl_mu_complex;
pub(crate) use impl_mu_simple;
pub(crate) use impl_mu_standard;
pub(crate) use impl_unmarshall_trait;
// Implementation of Marshall and UnMarshall macro for base TSS types.
impl_mu_aliases!(UINT32);
