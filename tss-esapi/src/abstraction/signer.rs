// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Module for exposing a [`signature::Signer`] interface for keys
//!
//! This modules presents objects held in a TPM over a [`signature::DigestSigner`] interface.
use crate::{
    abstraction::{
        public::AssociatedTpmCurve,
        transient::{KeyMaterial, KeyParams, TransientKeyContext},
        AssociatedHashingAlgorithm,
    },
    handles::KeyHandle,
    interface_types::algorithm::EccSchemeAlgorithm,
    structures::{
        Auth, Digest as TpmDigest, EccScheme, Public, Signature as TpmSignature, SignatureScheme,
    },
    utils::PublicKey as TpmPublicKey,
    Context, Error, WrapperErrorKind,
};

use std::{convert::TryFrom, ops::Add, sync::Mutex};

use digest::{Digest, FixedOutput, Output};
use ecdsa::{
    der::{MaxOverhead, MaxSize, Signature as DerSignature},
    hazmat::{DigestPrimitive, SignPrimitive},
    Signature, SignatureSize, VerifyingKey,
};
use elliptic_curve::{
    generic_array::ArrayLength,
    ops::Invert,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    subtle::CtOption,
    AffinePoint, CurveArithmetic, FieldBytesSize, PrimeCurve, PublicKey, Scalar,
};
use log::error;
use signature::{DigestSigner, Error as SigError, KeypairRef, Signer};
use x509_cert::{
    der::asn1::AnyRef,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier},
};

pub trait TpmSigner {
    fn public(&self) -> crate::Result<TpmPublicKey>;
    fn key_params(&self) -> crate::Result<KeyParams>;
    fn sign(&self, digest: TpmDigest) -> crate::Result<TpmSignature>;
}

impl TpmSigner for (Mutex<&'_ mut Context>, KeyHandle) {
    fn public(&self) -> crate::Result<TpmPublicKey> {
        let mut context = self.0.lock().expect("Mutex got poisoned");
        let (public, _, _) = context.read_public(self.1)?;

        TpmPublicKey::try_from(public)
    }

    fn key_params(&self) -> crate::Result<KeyParams> {
        let mut context = self.0.lock().expect("Mutex got poisoned");
        let (public, _, _) = context.read_public(self.1)?;

        match public {
            Public::Rsa { parameters, .. } => Ok(KeyParams::Rsa {
                size: parameters.key_bits(),
                scheme: parameters.rsa_scheme(),
                pub_exponent: parameters.exponent(),
            }),
            Public::Ecc { parameters, .. } => Ok(KeyParams::Ecc {
                curve: parameters.ecc_curve(),
                scheme: parameters.ecc_scheme(),
            }),
            other => {
                error!("Unsupported key parameter used: {other:?}");
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
        }
    }

    fn sign(&self, digest: TpmDigest) -> crate::Result<TpmSignature> {
        let mut context = self.0.lock().expect("Mutex got poisoned");
        context.sign(self.1, digest, SignatureScheme::Null, None)
    }
}

impl TpmSigner
    for (
        Mutex<&'_ mut TransientKeyContext>,
        KeyMaterial,
        KeyParams,
        Option<Auth>,
    )
{
    fn public(&self) -> crate::Result<TpmPublicKey> {
        Ok(self.1.public().clone())
    }

    fn key_params(&self) -> crate::Result<KeyParams> {
        Ok(self.2)
    }

    fn sign(&self, digest: TpmDigest) -> crate::Result<TpmSignature> {
        let mut context = self.0.lock().expect("Mutex got poisoned");
        context.sign(self.1.clone(), self.2, self.3.clone(), digest)
    }
}

/// [`EcSigner`] will sign a payload with an elliptic curve secret key stored on the TPM.
///
/// # Parameters
///
/// Parameter `C` describes the curve that is of use (Nist P-256, Nist P-384, ...)
///
/// ```no_run
/// # use std::sync::Mutex;
/// # use tss_esapi::{
/// #     abstraction::{EcSigner, transient::TransientKeyContextBuilder},
/// #     TctiNameConf
/// # };
/// use p256::NistP256;
/// use signature::Signer;
/// #
/// # // Create context
/// # let mut context = TransientKeyContextBuilder::new()
/// #     .with_tcti(
/// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
/// #     )
/// #     .build()
/// #     .expect("Failed to create Context");
///
/// let key_params = EcSigner::<NistP256, ()>::key_params_default();
/// let (tpm_km, _tpm_auth) = context
///     .create_key(key_params, 0)
///     .expect("Failed to create a private keypair");
///
/// let signer = EcSigner::<NistP256,_>::new((Mutex::new(&mut context), tpm_km, key_params, None))
///      .expect("Failed to create a signer");
/// let signature: p256::ecdsa::Signature = signer.sign(b"Hello Bob, Alice here.");
/// ```
#[derive(Debug)]
pub struct EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
{
    context: Ctx,
    verifying_key: VerifyingKey<C>,
}

impl<C, Ctx> EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,

    Ctx: TpmSigner,
{
    pub fn new(context: Ctx) -> Result<Self, Error> {
        match context.key_params()? {
            KeyParams::Ecc { curve, .. } if curve == C::TPM_CURVE => {}
            other => {
                error!(
                    "Unsupported key parameters: {other:?}, expected Ecc(curve: {:?})",
                    C::default()
                );
                return Err(Error::local_error(WrapperErrorKind::InvalidParam));
            }
        }

        let public_key = context.public()?;
        let public_key = PublicKey::try_from(&public_key)?;
        let verifying_key = VerifyingKey::from(public_key);

        Ok(Self {
            context,
            verifying_key,
        })
    }
}

impl<C, Ctx> EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
{
    /// Key parameters for this curve, selected digest is the one selected by DigestPrimitive
    pub fn key_params_default() -> KeyParams
    where
        C: DigestPrimitive,
        <C as DigestPrimitive>::Digest: FixedOutput<OutputSize = FieldBytesSize<C>>,
        <C as DigestPrimitive>::Digest: AssociatedHashingAlgorithm,
    {
        Self::key_params::<<C as DigestPrimitive>::Digest>()
    }

    /// Key parameters for this curve
    ///
    /// # Parameters
    ///
    /// The hashing algorithm `D` is the digest that will be used for signatures (SHA-256, SHA3-256, ...).
    pub fn key_params<D>() -> KeyParams
    where
        D: FixedOutput<OutputSize = FieldBytesSize<C>>,
        D: AssociatedHashingAlgorithm,
    {
        KeyParams::Ecc {
            curve: C::TPM_CURVE,
            scheme: EccScheme::create(EccSchemeAlgorithm::EcDsa, Some(D::TPM_DIGEST), None)
                .expect("Failed to create ecc scheme"),
        }
    }
}

impl<C, Ctx> AsRef<VerifyingKey<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }
}

impl<C, Ctx> KeypairRef for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type VerifyingKey = VerifyingKey<C>;
}

impl<C, Ctx, D> DigestSigner<D, Signature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    D: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<D>>,
    Ctx: TpmSigner,
{
    fn try_sign_digest(&self, digest: D) -> Result<Signature<C>, SigError> {
        let digest = TpmDigest::from(digest.finalize_fixed());

        //let key_params = Self::key_params::<D>();
        let signature = self.context.sign(digest).map_err(SigError::from_source)?;

        let TpmSignature::EcDsa(signature) = signature else {
            return Err(SigError::from_source(Error::local_error(
                WrapperErrorKind::InvalidParam,
            )));
        };

        let signature = Signature::try_from(signature).map_err(SigError::from_source)?;

        Ok(signature)
    }
}

impl<C, Ctx, D> DigestSigner<D, DerSignature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    D: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<D>>,

    MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,

    Ctx: TpmSigner,
{
    fn try_sign_digest(&self, digest: D) -> Result<DerSignature<C>, SigError> {
        let signature: Signature<_> = self.try_sign_digest(digest)?;
        Ok(signature.to_der())
    }
}

impl<C, Ctx> Signer<Signature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C: AssociatedTpmCurve,
    <C as DigestPrimitive>::Digest: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<<C as DigestPrimitive>::Digest>>,

    Ctx: TpmSigner,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, SigError> {
        self.try_sign_digest(C::Digest::new_with_prefix(msg))
    }
}

impl<C, Ctx> Signer<DerSignature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C: AssociatedTpmCurve,
    <C as DigestPrimitive>::Digest: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<<C as DigestPrimitive>::Digest>>,

    MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,

    Ctx: TpmSigner,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DerSignature<C>, SigError> {
        self.try_sign_digest(C::Digest::new_with_prefix(msg))
    }
}

impl<C, Ctx> SignatureAlgorithmIdentifier for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<C>::ALGORITHM_IDENTIFIER;
}
