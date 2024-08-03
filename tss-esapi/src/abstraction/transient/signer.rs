// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

//! Module for exposing a [`signature::Signer`] interface for keys
//!
//! This modules presents objects held in a TPM over a [`signature::DigestSigner`] interface.
use super::TransientKeyContext;
use crate::{
    abstraction::{
        public::AssociatedTpmCurve,
        transient::{KeyMaterial, KeyParams},
        AssociatedHashingAlgorithm,
    },
    interface_types::algorithm::EccSchemeAlgorithm,
    structures::{Auth, Digest as TpmDigest, EccScheme, Signature as TpmSignature},
    Error, WrapperErrorKind,
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
use signature::{DigestSigner, Error as SigError, KeypairRef, Signer};
use x509_cert::{
    der::asn1::AnyRef,
    spki::{AlgorithmIdentifier, AssociatedAlgorithmIdentifier, SignatureAlgorithmIdentifier},
};

/// [`EcSigner`] will sign a payload with an elliptic curve secret key stored on the TPM.
///
/// # Parameters
///
/// Parameter `C` describes the curve that is of use (Nist P-256, Nist P-384, ...)
///
/// ```no_run
/// # use tss_esapi::{
/// #     abstraction::transient::{EcSigner, TransientKeyContextBuilder},
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
/// let (tpm_km, _tpm_auth) = context
///     .create_key(EcSigner::<NistP256>::key_params_default(), 0)
///     .expect("Failed to create a private keypair");
///
/// let signer = EcSigner::<NistP256>::new(&mut context, tpm_km, None)
///      .expect("Failed to create a signer");
/// let signature: p256::ecdsa::Signature = signer.sign(b"Hello Bob, Alice here.");
/// ```
#[derive(Debug)]
pub struct EcSigner<'ctx, C>
where
    C: PrimeCurve + CurveArithmetic,
{
    context: Mutex<&'ctx mut TransientKeyContext>,
    key_material: KeyMaterial,
    key_auth: Option<Auth>,
    verifying_key: VerifyingKey<C>,
}

impl<'ctx, C> EcSigner<'ctx, C>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    pub fn new(
        context: &'ctx mut TransientKeyContext,
        key_material: KeyMaterial,
        key_auth: Option<Auth>,
    ) -> Result<Self, Error> {
        let context = Mutex::new(context);

        let public_key = PublicKey::try_from(key_material.public())?;
        let verifying_key = VerifyingKey::from(public_key);

        Ok(Self {
            context,
            key_material,
            key_auth,
            verifying_key,
        })
    }
}

impl<C> EcSigner<'_, C>
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

impl<C> AsRef<VerifyingKey<C>> for EcSigner<'_, C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    fn as_ref(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }
}

impl<C> KeypairRef for EcSigner<'_, C>
where
    C: PrimeCurve + CurveArithmetic,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type VerifyingKey = VerifyingKey<C>;
}

impl<C, D> DigestSigner<D, Signature<C>> for EcSigner<'_, C>
where
    C: PrimeCurve + CurveArithmetic,
    C: AssociatedTpmCurve,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    D: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<D>>,
{
    fn try_sign_digest(&self, digest: D) -> Result<Signature<C>, SigError> {
        let digest = TpmDigest::from(digest.finalize_fixed());

        let key_params = Self::key_params::<D>();
        let mut context = self.context.lock().expect("Mutex got poisoned");
        let signature = context
            .sign(
                self.key_material.clone(),
                key_params,
                self.key_auth.clone(),
                digest,
            )
            .map_err(SigError::from_source)?;

        let TpmSignature::EcDsa(signature) = signature else {
            return Err(SigError::from_source(Error::local_error(
                WrapperErrorKind::InvalidParam,
            )));
        };

        let signature = Signature::try_from(signature).map_err(SigError::from_source)?;

        Ok(signature)
    }
}

impl<C, D> DigestSigner<D, DerSignature<C>> for EcSigner<'_, C>
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
{
    fn try_sign_digest(&self, digest: D) -> Result<DerSignature<C>, SigError> {
        let signature: Signature<_> = self.try_sign_digest(digest)?;
        Ok(signature.to_der())
    }
}

impl<C> Signer<Signature<C>> for EcSigner<'_, C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C: AssociatedTpmCurve,
    <C as DigestPrimitive>::Digest: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<<C as DigestPrimitive>::Digest>>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, SigError> {
        self.try_sign_digest(C::Digest::new_with_prefix(msg))
    }
}

impl<C> Signer<DerSignature<C>> for EcSigner<'_, C>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    C: AssociatedTpmCurve,
    <C as DigestPrimitive>::Digest: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    TpmDigest: From<Output<<C as DigestPrimitive>::Digest>>,

    MaxSize<C>: ArrayLength<u8>,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArrayLength<u8>,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DerSignature<C>, SigError> {
        self.try_sign_digest(C::Digest::new_with_prefix(msg))
    }
}

impl<C> SignatureAlgorithmIdentifier for EcSigner<'_, C>
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
