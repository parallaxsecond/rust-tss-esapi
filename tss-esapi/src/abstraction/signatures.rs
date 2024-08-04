// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{structures::EccSignature, Error, Result, WrapperErrorKind};

use std::convert::TryFrom;

use ecdsa::SignatureSize;
use elliptic_curve::{
    generic_array::{typenum::Unsigned, ArrayLength},
    FieldBytes, FieldBytesSize, PrimeCurve,
};

#[cfg(feature = "rsa")]
use crate::structures::Signature;

impl<C> TryFrom<EccSignature> for ecdsa::Signature<C>
where
    C: PrimeCurve,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn try_from(signature: EccSignature) -> Result<Self> {
        let r = signature.signature_r().as_slice();
        let s = signature.signature_s().as_slice();

        if r.len() != FieldBytesSize::<C>::USIZE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        if s.len() != FieldBytesSize::<C>::USIZE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let signature = ecdsa::Signature::from_scalars(
            FieldBytes::<C>::from_slice(r).clone(),
            FieldBytes::<C>::from_slice(s).clone(),
        )
        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;
        Ok(signature)
    }
}

// Note: this does not implement `TryFrom<RsaSignature>` because `RsaSignature` does not carry the
// information whether the signatures was generated using PKCS#1v1.5 or PSS.
#[cfg(feature = "rsa")]
impl TryFrom<Signature> for rsa::pkcs1v15::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Self> {
        let Signature::RsaSsa(signature) = signature else {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        };

        Self::try_from(signature.signature().as_bytes())
            .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))
    }
}

// Note: this does not implement `TryFrom<RsaSignature>` because `RsaSignature` does not carry the
// information whether the signatures was generated using PKCS#1v1.5 or PSS.
#[cfg(feature = "rsa")]
impl TryFrom<Signature> for rsa::pss::Signature {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Self> {
        let Signature::RsaPss(signature) = signature else {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        };

        Self::try_from(signature.signature().as_bytes())
            .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))
    }
}
