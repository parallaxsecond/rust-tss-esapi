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
    hazmat::DigestAlgorithm,
    EcdsaCurve, Signature, SignatureSize, VerifyingKey,
};
use elliptic_curve::{
    array::ArraySize,
    ops::Invert,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
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
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
{
    context: Ctx,
    verifying_key: VerifyingKey<C>,
}

impl<C, Ctx> EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    C: AssociatedTpmCurve,
    FieldBytesSize<C>: ModulusSize,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,

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
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    C: AssociatedTpmCurve,
{
    /// Key parameters for this curve, selected digest is the one selected by DigestAlgorithm
    pub fn key_params_default() -> KeyParams
    where
        C: DigestAlgorithm,
        <C as DigestAlgorithm>::Digest: FixedOutput,
        <C as DigestAlgorithm>::Digest: AssociatedHashingAlgorithm,
    {
        Self::key_params::<<C as DigestAlgorithm>::Digest>()
    }

    /// Key parameters for this curve
    ///
    /// # Parameters
    ///
    /// The hashing algorithm `D` is the digest that will be used for signatures (SHA-256, SHA3-256, ...).
    pub fn key_params<D>() -> KeyParams
    where
        D: FixedOutput,
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
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
{
    fn as_ref(&self) -> &VerifyingKey<C> {
        &self.verifying_key
    }
}

impl<C, Ctx> KeypairRef for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
{
    type VerifyingKey = VerifyingKey<C>;
}

impl<C, Ctx, D> DigestSigner<D, Signature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    C: AssociatedTpmCurve,
    D: Digest + FixedOutput,
    D: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    TpmDigest: From<Output<D>>,
    Ctx: TpmSigner,
{
    fn try_sign_digest<F: Fn(&mut D) -> Result<(), SigError>>(
        &self,
        f: F,
    ) -> Result<Signature<C>, SigError> {
        let mut digest = D::new();
        f(&mut digest)?;
        let digest = TpmDigest::from(digest.finalize_fixed());

        //let key_params = Self::key_params::<D>();
        let signature = self.context.sign(digest).map_err(SigError::from_source)?;

        let TpmSignature::EcDsa(signature) = signature else {
            return Err(SigError::from_source(Error::local_error(
                WrapperErrorKind::InvalidParam,
            )));
        };

        let signature = Signature::try_from(&signature).map_err(SigError::from_source)?;

        Ok(signature)
    }
}

impl<C, Ctx, D> DigestSigner<D, DerSignature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    C: AssociatedTpmCurve,
    D: Digest + FixedOutput,
    D: AssociatedHashingAlgorithm,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    TpmDigest: From<Output<D>>,

    MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArraySize,

    Ctx: TpmSigner,
{
    fn try_sign_digest<F: Fn(&mut D) -> Result<(), SigError>>(
        &self,
        f: F,
    ) -> Result<DerSignature<C>, SigError> {
        let signature: Signature<_> = self.try_sign_digest(f)?;
        Ok(signature.to_der())
    }
}

impl<C, Ctx> Signer<Signature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve + DigestAlgorithm,
    C: AssociatedTpmCurve,
    <C as DigestAlgorithm>::Digest: AssociatedHashingAlgorithm + FixedOutput,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    TpmDigest: From<Output<<C as DigestAlgorithm>::Digest>>,

    Ctx: TpmSigner,
{
    fn try_sign(&self, msg: &[u8]) -> Result<Signature<C>, SigError> {
        self.try_sign_digest(|d: &mut C::Digest| {
            Digest::update(d, msg);
            Ok(())
        })
    }
}

impl<C, Ctx> Signer<DerSignature<C>> for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve + DigestAlgorithm,
    C: AssociatedTpmCurve,
    <C as DigestAlgorithm>::Digest: AssociatedHashingAlgorithm + FixedOutput,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    TpmDigest: From<Output<<C as DigestAlgorithm>::Digest>>,

    MaxSize<C>: ArraySize,
    <FieldBytesSize<C> as Add>::Output: Add<MaxOverhead> + ArraySize,

    Ctx: TpmSigner,
{
    fn try_sign(&self, msg: &[u8]) -> Result<DerSignature<C>, SigError> {
        self.try_sign_digest(|d: &mut C::Digest| {
            Digest::update(d, msg);
            Ok(())
        })
    }
}

impl<C, Ctx> SignatureAlgorithmIdentifier for EcSigner<C, Ctx>
where
    C: PrimeCurve + CurveArithmetic + EcdsaCurve,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>>,
    SignatureSize<C>: ArraySize,
    Signature<C>: AssociatedAlgorithmIdentifier<Params = AnyRef<'static>>,
{
    type Params = AnyRef<'static>;

    const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
        Signature::<C>::ALGORITHM_IDENTIFIER;
}

#[cfg(feature = "rsa")]
mod rsa {
    use super::TpmSigner;

    use crate::{
        abstraction::{signer::KeyParams, AssociatedHashingAlgorithm},
        structures::{Digest as TpmDigest, RsaScheme},
        Error, WrapperErrorKind,
    };

    use std::fmt;

    use digest::{Digest, FixedOutput, Output};
    use log::error;
    use pkcs8::AssociatedOid;
    use signature::{DigestSigner, Error as SigError, Keypair, Signer};
    use x509_cert::{
        der::asn1::AnyRef,
        spki::{
            self, AlgorithmIdentifier, AlgorithmIdentifierOwned, AssociatedAlgorithmIdentifier,
            DynSignatureAlgorithmIdentifier, SignatureAlgorithmIdentifier,
        },
    };

    use ::rsa::{pkcs1v15, pss, RsaPublicKey};

    /// [`RsaPkcsSigner`] will sign a payload with an RSA secret key stored on the TPM.
    ///
    /// ```no_run
    /// # use std::sync::Mutex;
    /// # use tss_esapi::{
    /// #     abstraction::{RsaPkcsSigner, transient::{TransientKeyContextBuilder, KeyParams}},
    /// #     interface_types::{algorithm::{HashingAlgorithm, RsaSchemeAlgorithm}, key_bits::RsaKeyBits},
    /// #     structures::{RsaExponent, RsaScheme},
    /// #     TctiNameConf
    /// # };
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
    /// let key_params = KeyParams::Rsa {
    ///     size: RsaKeyBits::Rsa1024,
    ///     scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
    ///         .expect("Failed to create RSA scheme"),
    ///     pub_exponent: RsaExponent::default(),
    /// };
    /// let (tpm_km, _tpm_auth) = context
    ///     .create_key(key_params, 0)
    ///     .expect("Failed to create a private keypair");
    ///
    /// let signer = RsaPkcsSigner::<_, sha2::Sha256>::new((Mutex::new(&mut context), tpm_km, key_params, None))
    ///      .expect("Failed to create a signer");
    /// let signature  = signer.sign(b"Hello Bob, Alice here.");
    /// ```
    #[derive(Debug)]
    pub struct RsaPkcsSigner<Ctx, D>
    where
        D: Digest,
    {
        context: Ctx,
        verifying_key: pkcs1v15::VerifyingKey<D>,
    }

    impl<Ctx, D> RsaPkcsSigner<Ctx, D>
    where
        Ctx: TpmSigner,
        D: Digest + AssociatedOid + AssociatedHashingAlgorithm + fmt::Debug,
    {
        pub fn new(context: Ctx) -> Result<Self, Error> {
            match context.key_params()? {
                KeyParams::Rsa {
                    scheme: RsaScheme::RsaSsa(hash),
                    ..
                } if hash.hashing_algorithm() == D::TPM_DIGEST => {}
                other => {
                    error!(
                        "Unsupported key parameters: {other:?}, expected RsaSsa({:?})",
                        D::new()
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
            }

            let public_key = context.public()?;
            let public_key = RsaPublicKey::try_from(&public_key)?;
            let verifying_key = pkcs1v15::VerifyingKey::new(public_key);

            Ok(Self {
                context,
                verifying_key,
            })
        }
    }

    impl<Ctx, D> Keypair for RsaPkcsSigner<Ctx, D>
    where
        D: Digest,
    {
        type VerifyingKey = pkcs1v15::VerifyingKey<D>;

        fn verifying_key(&self) -> Self::VerifyingKey {
            self.verifying_key.clone()
        }
    }

    impl<Ctx, D> DigestSigner<D, pkcs1v15::Signature> for RsaPkcsSigner<Ctx, D>
    where
        D: Digest + FixedOutput,
        D: AssociatedHashingAlgorithm,
        TpmDigest: From<Output<D>>,
        Ctx: TpmSigner,
    {
        fn try_sign_digest<F: Fn(&mut D) -> Result<(), SigError>>(
            &self,
            f: F,
        ) -> Result<pkcs1v15::Signature, SigError> {
            let mut digest = D::new();
            f(&mut digest)?;
            let digest = TpmDigest::from(digest.finalize_fixed());

            //let key_params = Self::key_params::<D>();
            let signature = self.context.sign(digest).map_err(SigError::from_source)?;

            let signature =
                pkcs1v15::Signature::try_from(&signature).map_err(SigError::from_source)?;

            Ok(signature)
        }
    }

    impl<Ctx, D> Signer<pkcs1v15::Signature> for RsaPkcsSigner<Ctx, D>
    where
        D: Digest + FixedOutput,
        D: AssociatedHashingAlgorithm,
        TpmDigest: From<Output<D>>,
        Ctx: TpmSigner,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<pkcs1v15::Signature, SigError> {
            self.try_sign_digest(|d: &mut D| {
                Digest::update(d, msg);
                Ok(())
            })
        }
    }

    impl<Ctx, D> SignatureAlgorithmIdentifier for RsaPkcsSigner<Ctx, D>
    where
        D: Digest + pkcs1v15::RsaSignatureAssociatedOid,
    {
        type Params = AnyRef<'static>;

        const SIGNATURE_ALGORITHM_IDENTIFIER: AlgorithmIdentifier<Self::Params> =
            pkcs1v15::SigningKey::<D>::ALGORITHM_IDENTIFIER;
    }

    /// [`RsaPssSigner`] will sign a payload with an RSA secret key stored on the TPM.
    ///
    /// ```no_run
    /// # use std::sync::Mutex;
    /// # use tss_esapi::{
    /// #     abstraction::{RsaPssSigner, transient::{TransientKeyContextBuilder, KeyParams}},
    /// #     interface_types::{algorithm::{HashingAlgorithm, RsaSchemeAlgorithm}, key_bits::RsaKeyBits},
    /// #     structures::{RsaExponent, RsaScheme},
    /// #     TctiNameConf
    /// # };
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
    /// let key_params = KeyParams::Rsa {
    ///     size: RsaKeyBits::Rsa1024,
    ///     scheme: RsaScheme::create(RsaSchemeAlgorithm::RsaPss, Some(HashingAlgorithm::Sha256))
    ///         .expect("Failed to create RSA scheme"),
    ///     pub_exponent: RsaExponent::default(),
    /// };
    /// let (tpm_km, _tpm_auth) = context
    ///     .create_key(key_params, 0)
    ///     .expect("Failed to create a private keypair");
    ///
    /// let signer = RsaPssSigner::<_, sha2::Sha256>::new((Mutex::new(&mut context), tpm_km, key_params, None))
    ///      .expect("Failed to create a signer");
    /// let signature  = signer.sign(b"Hello Bob, Alice here.");
    /// ```
    #[derive(Debug)]
    pub struct RsaPssSigner<Ctx, D>
    where
        D: Digest,
    {
        context: Ctx,
        verifying_key: pss::VerifyingKey<D>,
    }

    impl<Ctx, D> RsaPssSigner<Ctx, D>
    where
        Ctx: TpmSigner,
        D: Digest + AssociatedHashingAlgorithm + fmt::Debug,
    {
        pub fn new(context: Ctx) -> Result<Self, Error> {
            match context.key_params()? {
                KeyParams::Rsa {
                    scheme: RsaScheme::RsaPss(hash),
                    ..
                } if hash.hashing_algorithm() == D::TPM_DIGEST => {}
                other => {
                    error!(
                        "Unsupported key parameters: {other:?}, expected RsaSsa({:?})",
                        D::new()
                    );
                    return Err(Error::local_error(WrapperErrorKind::InvalidParam));
                }
            }

            let public_key = context.public()?;
            let public_key = RsaPublicKey::try_from(&public_key)?;
            let verifying_key = pss::VerifyingKey::new(public_key);

            Ok(Self {
                context,
                verifying_key,
            })
        }
    }

    impl<Ctx, D> Keypair for RsaPssSigner<Ctx, D>
    where
        D: Digest,
    {
        type VerifyingKey = pss::VerifyingKey<D>;

        fn verifying_key(&self) -> Self::VerifyingKey {
            self.verifying_key.clone()
        }
    }

    impl<Ctx, D> DigestSigner<D, pss::Signature> for RsaPssSigner<Ctx, D>
    where
        D: Digest + FixedOutput,
        D: AssociatedHashingAlgorithm,
        TpmDigest: From<Output<D>>,
        Ctx: TpmSigner,
    {
        fn try_sign_digest<F: Fn(&mut D) -> Result<(), SigError>>(
            &self,
            f: F,
        ) -> Result<pss::Signature, SigError> {
            let mut digest = D::new();
            f(&mut digest)?;
            let digest = TpmDigest::from(digest.finalize_fixed());

            let signature = self.context.sign(digest).map_err(SigError::from_source)?;

            let signature = pss::Signature::try_from(&signature).map_err(SigError::from_source)?;

            Ok(signature)
        }
    }

    impl<Ctx, D> Signer<pss::Signature> for RsaPssSigner<Ctx, D>
    where
        D: Digest + FixedOutput,
        D: AssociatedHashingAlgorithm,
        TpmDigest: From<Output<D>>,
        Ctx: TpmSigner,
    {
        fn try_sign(&self, msg: &[u8]) -> Result<pss::Signature, SigError> {
            self.try_sign_digest(|d: &mut D| {
                Digest::update(d, msg);
                Ok(())
            })
        }
    }

    impl<Ctx, D> DynSignatureAlgorithmIdentifier for RsaPssSigner<Ctx, D>
    where
        D: Digest + AssociatedOid,
    {
        fn signature_algorithm_identifier(&self) -> spki::Result<AlgorithmIdentifierOwned> {
            pss::get_default_pss_signature_algo_id::<D>()
        }
    }
}

#[cfg(feature = "rsa")]
pub use self::rsa::{RsaPkcsSigner, RsaPssSigner};
