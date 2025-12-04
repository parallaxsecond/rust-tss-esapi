// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::interface_types::ecc::EccCurve;
use crate::structures::Public;
use crate::utils::PublicKey as TpmPublicKey;
use crate::{Error, WrapperErrorKind};

use core::convert::TryFrom;
use elliptic_curve::{
    array::typenum::Unsigned,
    sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey,
};

use x509_cert::spki::SubjectPublicKeyInfoOwned;

#[cfg(feature = "rsa")]
use {
    crate::structures::RsaExponent,
    rsa::{BoxedUint, RsaPublicKey},
};

#[cfg(any(
    feature = "p192",
    feature = "p224",
    feature = "p256",
    feature = "p384",
    feature = "p521",
    feature = "rsa",
    feature = "sm2"
))]
use pkcs8::EncodePublicKey;

/// Default exponent for RSA keys.
// Also known as 0x10001
#[cfg(feature = "rsa")]
const RSA_DEFAULT_EXP: u64 = 65537;

impl<C> TryFrom<&Public> for PublicKey<C>
where
    C: CurveArithmetic + AssociatedTpmCurve,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = Error;

    fn try_from(value: &Public) -> Result<Self, Self::Error> {
        match value {
            Public::Ecc {
                parameters, unique, ..
            } => {
                if parameters.ecc_curve() != C::TPM_CURVE {
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }

                let x = unique.x().as_bytes();
                let y = unique.y().as_bytes();

                let encoded_point = EncodedPoint::<C>::from_affine_coordinates(
                    x.try_into()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
                    y.try_into()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
                    false,
                );
                let public_key = PublicKey::<C>::try_from(&encoded_point)
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

                Ok(public_key)
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&Public> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: &Public) -> Result<Self, Self::Error> {
        match value {
            Public::Rsa {
                unique, parameters, ..
            } => {
                let exponent = match parameters.exponent() {
                    RsaExponent::ZERO_EXPONENT => BoxedUint::from(RSA_DEFAULT_EXP),
                    _ => BoxedUint::from(parameters.exponent().value()),
                };
                let modulus = BoxedUint::from_be_slice_vartime(unique.as_bytes());

                let public_key = RsaPublicKey::new(modulus, exponent)
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

                Ok(public_key)
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

impl TryFrom<&Public> for SubjectPublicKeyInfoOwned {
    type Error = Error;

    /// Converts [`crate::structures::Public::Rsa`] and [`crate::structures::Public::Ecc`] to [`x509_cert::spki::SubjectPublicKeyInfoOwned`].
    ///
    /// # Details
    /// The result can be used to convert TPM public keys to DER using `x509-cert`.
    ///
    /// # Errors
    /// * if other instances of [`crate::structures::Public`] are used `UnsupportedParam` will be returned.
    fn try_from(value: &Public) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "rsa")]
            Public::Rsa { .. } => {
                let public_key = RsaPublicKey::try_from(value)?;

                Ok(public_key
                    .to_public_key_der()
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?
                    .decode_msg::<Self>()
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?)
            }
            #[allow(unused)]
            Public::Ecc { parameters, .. } => {
                macro_rules! read_key {
                    ($key_type:ty) => {
                        if parameters.ecc_curve() == <$key_type>::TPM_CURVE {
                            let public_key = PublicKey::<$key_type>::try_from(value)?;

                            return public_key
                                .to_public_key_der()
                                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?
                                .decode_msg::<Self>()
                                .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam));
                        }
                    };
                }

                #[cfg(feature = "p192")]
                read_key!(p192::NistP192);
                #[cfg(feature = "p224")]
                read_key!(p224::NistP224);
                #[cfg(feature = "p256")]
                read_key!(p256::NistP256);
                #[cfg(feature = "p384")]
                read_key!(p384::NistP384);
                #[cfg(feature = "p521")]
                read_key!(p521::NistP521);
                #[cfg(feature = "sm2")]
                read_key!(sm2::Sm2);

                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

impl<C> TryFrom<&TpmPublicKey> for PublicKey<C>
where
    C: CurveArithmetic + AssociatedTpmCurve,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    type Error = Error;

    fn try_from(value: &TpmPublicKey) -> Result<Self, Self::Error> {
        match value {
            TpmPublicKey::Ecc { x, y } => {
                let x = x.as_slice();
                let y = y.as_slice();

                if x.len() != FieldBytesSize::<C>::USIZE {
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
                if y.len() != FieldBytesSize::<C>::USIZE {
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }

                let encoded_point = EncodedPoint::<C>::from_affine_coordinates(
                    x.try_into()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
                    y.try_into()
                        .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?,
                    false,
                );

                let public_key = PublicKey::<C>::try_from(&encoded_point)
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

                Ok(public_key)
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&TpmPublicKey> for RsaPublicKey {
    type Error = Error;

    fn try_from(value: &TpmPublicKey) -> Result<Self, Self::Error> {
        match value {
            TpmPublicKey::Rsa(modulus) => {
                let exponent = BoxedUint::from(RSA_DEFAULT_EXP);
                let modulus = BoxedUint::from_be_slice_vartime(modulus.as_slice());

                let public_key = RsaPublicKey::new(modulus, exponent)
                    .map_err(|_| Error::local_error(WrapperErrorKind::InvalidParam))?;

                Ok(public_key)
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

/// Provides the value of the curve used in this crate for the specific curve.
pub trait AssociatedTpmCurve {
    /// Value of the curve when interacting with the TPM.
    const TPM_CURVE: EccCurve;
}

#[cfg(feature = "p192")]
impl AssociatedTpmCurve for p192::NistP192 {
    const TPM_CURVE: EccCurve = EccCurve::NistP192;
}

#[cfg(feature = "p224")]
impl AssociatedTpmCurve for p224::NistP224 {
    const TPM_CURVE: EccCurve = EccCurve::NistP224;
}

#[cfg(feature = "p256")]
impl AssociatedTpmCurve for p256::NistP256 {
    const TPM_CURVE: EccCurve = EccCurve::NistP256;
}

#[cfg(feature = "p384")]
impl AssociatedTpmCurve for p384::NistP384 {
    const TPM_CURVE: EccCurve = EccCurve::NistP384;
}

#[cfg(feature = "p521")]
impl AssociatedTpmCurve for p521::NistP521 {
    const TPM_CURVE: EccCurve = EccCurve::NistP521;
}

#[cfg(feature = "sm2")]
impl AssociatedTpmCurve for sm2::Sm2 {
    const TPM_CURVE: EccCurve = EccCurve::Sm2P256;
}
