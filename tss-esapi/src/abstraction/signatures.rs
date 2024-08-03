// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{structures::EccSignature, Error, Result, WrapperErrorKind};

use std::convert::TryFrom;

use ecdsa::SignatureSize;
use elliptic_curve::{
    generic_array::{typenum::Unsigned, ArrayLength},
    FieldBytes, FieldBytesSize, PrimeCurve,
};

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

// TODO(baloo): impl TryFrom<RsaSignature> for rsa::pkcs1v15::Signature
// TODO(baloo): impl TryFrom<RsaSignature> for rsa::pss::Signature
