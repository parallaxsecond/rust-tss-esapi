// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result, WrapperErrorKind,
    abstraction::AssociatedHashingAlgorithm,
    structures::{EccParameter, EccSignature, Signature},
};

use std::convert::TryFrom;

use ecdsa::{DigestAlgorithm, EcdsaCurve, SignatureSize};
use elliptic_curve::{
    FieldBytes, FieldBytesSize, PrimeCurve,
    array::{ArraySize, typenum::Unsigned},
};

impl<C> TryFrom<&EccSignature> for ecdsa::Signature<C>
where
    C: PrimeCurve + EcdsaCurve,
    SignatureSize<C>: ArraySize,
{
    type Error = Error;

    fn try_from(signature: &EccSignature) -> Result<Self> {
        let r = signature.signature_r().as_slice();
        let s = signature.signature_s().as_slice();

        if r.len() != FieldBytesSize::<C>::USIZE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        if s.len() != FieldBytesSize::<C>::USIZE {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }

        let signature = ecdsa::Signature::from_scalars(
            FieldBytes::<C>::try_from(r)
                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
            FieldBytes::<C>::try_from(s)
                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
        )
        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;
        Ok(signature)
    }
}

impl<C> TryFrom<&Signature> for ecdsa::Signature<C>
where
    C: PrimeCurve + EcdsaCurve,
    SignatureSize<C>: ArraySize,
{
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<Self> {
        let Signature::EcDsa(signature) = signature else {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        };
        Self::try_from(signature)
    }
}

// Note: this does not implement `TryFrom<RsaSignature>` because `RsaSignature` does not carry the
// information whether the signatures was generated using PKCS#1v1.5 or PSS.
#[cfg(feature = "rsa")]
impl TryFrom<&Signature> for rsa::pkcs1v15::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<Self> {
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
impl TryFrom<&Signature> for rsa::pss::Signature {
    type Error = Error;

    fn try_from(signature: &Signature) -> Result<Self> {
        let Signature::RsaPss(signature) = signature else {
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        };

        Self::try_from(signature.signature().as_bytes())
            .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))
    }
}

impl<C> TryFrom<&ecdsa::Signature<C>> for EccSignature
where
    C: PrimeCurve + DigestAlgorithm,
    C::Digest: AssociatedHashingAlgorithm,
    SignatureSize<C>: ArraySize,
{
    type Error = Error;

    fn try_from(signature: &ecdsa::Signature<C>) -> Result<Self> {
        let (r, s) = signature.split_bytes();

        let signature_r = EccParameter::from_bytes(r.as_slice())
            .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;
        let signature_s = EccParameter::from_bytes(s.as_slice())
            .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

        EccSignature::create(C::Digest::TPM_DIGEST, signature_r, signature_s)
    }
}

impl<C> TryFrom<&ecdsa::Signature<C>> for Signature
where
    C: PrimeCurve + DigestAlgorithm,
    C::Digest: AssociatedHashingAlgorithm,
    SignatureSize<C>: ArraySize,
{
    type Error = Error;

    fn try_from(signature: &ecdsa::Signature<C>) -> Result<Self> {
        let ecc_signature = EccSignature::try_from(signature)?;
        Ok(Signature::EcDsa(ecc_signature))
    }
}
