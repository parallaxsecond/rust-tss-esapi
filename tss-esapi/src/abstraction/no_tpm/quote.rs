// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::error::Error;
use crate::error::Result;
use crate::WrapperErrorKind;
use crate::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Attest, AttestInfo, DigestList, PcrSelectionList, Public, QuoteInfo, Signature},
    traits::Marshall,
};
use digest::{Digest, DynDigest};

#[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
use crate::{abstraction::public::AssociatedTpmCurve, structures::EccSignature};
#[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
use ecdsa::{hazmat::DigestAlgorithm, PrimeCurve, SignatureSize, VerifyingKey};
#[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
use elliptic_curve::{
    array::ArraySize,
    point::AffinePoint,
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    CurveArithmetic, FieldBytesSize,
};
#[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
use signature::DigestVerifier;

#[cfg(feature = "rsa")]
use rsa::{pkcs1v15, pss, RsaPublicKey};
#[cfg(feature = "rsa")]
use signature::Verifier;

#[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
fn verify_ecdsa<C>(
    public: &Public,
    message: &[u8],
    signature: &EccSignature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool>
where
    C: PrimeCurve + CurveArithmetic + DigestAlgorithm + AssociatedTpmCurve,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    SignatureSize<C>: ArraySize,
    FieldBytesSize<C>: ModulusSize,
{
    let Ok(signature) = ecdsa::Signature::<C>::try_from(signature) else {
        return Ok(false);
    };
    let Ok(public) = elliptic_curve::PublicKey::<C>::try_from(public) else {
        return Ok(false);
    };

    let verifying_key = VerifyingKey::from(public);

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => Ok(verifying_key
            .verify_digest(
                |d: &mut sha1::Sha1| {
                    Digest::update(d, message);
                    Ok(())
                },
                &signature,
            )
            .is_ok()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => Ok(verifying_key
            .verify_digest(
                |d: &mut sha2::Sha256| {
                    Digest::update(d, message);
                    Ok(())
                },
                &signature,
            )
            .is_ok()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => Ok(verifying_key
            .verify_digest(
                |d: &mut sha2::Sha384| {
                    Digest::update(d, message);
                    Ok(())
                },
                &signature,
            )
            .is_ok()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => Ok(verifying_key
            .verify_digest(
                |d: &mut sha2::Sha512| {
                    Digest::update(d, message);
                    Ok(())
                },
                &signature,
            )
            .is_ok()),
        _ => Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
    }
}

#[cfg(feature = "rsa")]
fn verify_rsa_pss(
    public: &Public,
    message: &[u8],
    signature: &pss::Signature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool> {
    let rsa_key = RsaPublicKey::try_from(public)?;

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let verifying_key = pss::VerifyingKey::<sha1::Sha1>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha256>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha384>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => {
            let verifying_key = pss::VerifyingKey::<sha2::Sha512>::from(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        _ => Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
    }
}

#[cfg(feature = "rsa")]
fn verify_rsa_pkcs1v15(
    public: &Public,
    message: &[u8],
    signature: &pkcs1v15::Signature,
    hashing_algorithm: HashingAlgorithm,
) -> Result<bool> {
    let rsa_key = RsaPublicKey::try_from(public)?;

    match hashing_algorithm {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha1::Sha1>::new(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha384>::new(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => {
            let verifying_key = pkcs1v15::VerifyingKey::<sha2::Sha512>::new(rsa_key);
            Ok(verifying_key.verify(message, signature).is_ok())
        }
        _ => Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
    }
}

fn checkquote_pcr_digests(
    quote: &QuoteInfo,
    selections: &PcrSelectionList,
    digests: &DigestList,
    hash_alg: HashingAlgorithm,
) -> Result<bool> {
    if selections != quote.pcr_selection() {
        return Ok(false);
    }
    let digests_val = digests.value();
    let mut digest_pos = 0;
    let mut hasher: Box<dyn DynDigest> = match hash_alg {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => Box::new(sha1::Sha1::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => Box::new(sha2::Sha256::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha384 => Box::new(sha2::Sha384::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha512 => Box::new(sha2::Sha512::new()),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };

    for selection in selections.get_selections() {
        let sel_count = selection.selected().len();
        if digest_pos + sel_count > digests.len() {
            return Err(Error::WrapperError(WrapperErrorKind::WrongParamSize));
        }
        for _ in 0..sel_count {
            hasher.update(&digests_val[digest_pos]);
            digest_pos += 1;
        }
    }
    if digest_pos != digests.len() {
        return Err(Error::WrapperError(WrapperErrorKind::WrongParamSize));
    }
    let digest = hasher.finalize();
    Ok(digest.as_ref() == quote.pcr_digest().as_ref())
}

/// Verify a quote
///
/// # Arguments
/// * `attest` - Attestation data containing a quote
/// * `signature` - Signature for the attestation data
/// * `public` - TPM2 public struct which contains the public key for verification
/// * `pcr_data` - Optional pcr values to verify
/// * `qualifying_data` - qualifying data to verify
///
/// # Returns
/// The command returns `true` if the quote is valid or `false` otherwise.
///
/// # Errors
/// * if the qualifying data provided is too long, a `WrongParamSize` wrapper error will be returned
///
/// # Examples
///
/// ```rust
/// # use std::convert::TryFrom;
/// # use tss_esapi::{
/// #     attributes::SessionAttributes,
/// #     abstraction::{ak, ek, AsymmetricAlgorithmSelection, no_tpm},
/// #     constants::SessionType, Context,
/// #     interface_types::{
/// #         algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
/// #         ecc::EccCurve,
/// #     },
/// #     structures::{
/// #         Data, PcrSelectionListBuilder, PcrSlot,
/// #         SignatureScheme, SymmetricDefinition,
/// #     },
/// #     TctiNameConf,
/// # };
/// # let mut context =
/// #     Context::new(
/// #         TctiNameConf::from_environment_variable().expect("Failed to get TCTI"),
/// #     ).expect("Failed to create Context");
/// # let session = context
/// #     .start_auth_session(
/// #         None,
/// #         None,
/// #         None,
/// #         SessionType::Hmac,
/// #         SymmetricDefinition::AES_256_CFB,
/// #         tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256,
/// #     )
/// #     .expect("Failed to create session")
/// #     .expect("Received invalid handle");
/// # let (session_attributes, session_attributes_mask) = SessionAttributes::builder()
/// #     .with_decrypt(true)
/// #     .with_encrypt(true)
/// #     .build();
/// # context.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)
/// #     .expect("Failed to set attributes on session");
/// # context.set_sessions((Some(session), None, None));
/// # let qualifying_data = vec![0xff; 16];
/// # let ek_ecc = ek::create_ek_object(
/// #     &mut context,
/// #     AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
/// #     None,
/// # )
/// # .unwrap();
/// # let ak_res = ak::create_ak(
/// #     &mut context,
/// #     ek_ecc,
/// #     HashingAlgorithm::Sha256,
/// #     AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
/// #     SignatureSchemeAlgorithm::EcDsa,
/// #     None,
/// #     None,
/// # )
/// # .unwrap();
/// # let ak_ecc = ak::load_ak(
/// #     &mut context,
/// #     ek_ecc,
/// #     None,
/// #     ak_res.out_private,
/// #     ak_res.out_public.clone(),
/// # )
/// # .unwrap();
/// # let pcr_selection_list = PcrSelectionListBuilder::new()
/// #     .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot2])
/// #     .build()
/// #     .expect("Failed to create PcrSelectionList");
/// let (attest, signature) = context
///     .quote(
///         ak_ecc,
///         Data::try_from(qualifying_data.clone()).unwrap(),
///         SignatureScheme::Null,
///         pcr_selection_list.clone(),
///     )
///     .expect("Failed to get a quote");
/// let (_update_counter, pcr_sel, pcr_data) = context
///     .execute_without_session(|ctx| ctx.pcr_read(pcr_selection_list))
///     .unwrap();
/// let public = ak_res.out_public;
/// no_tpm::checkquote(
///     &attest,
///     &signature,
///     &public,
///     &Some((pcr_sel.clone(), pcr_data.clone())),
///     &qualifying_data
/// )
/// .unwrap();
/// ```
pub fn checkquote(
    attest: &Attest,
    signature: &Signature,
    public: &Public,
    pcr_data: &Option<(PcrSelectionList, DigestList)>,
    qualifying_data: &Vec<u8>,
) -> Result<bool> {
    let quote = if let AttestInfo::Quote { info } = attest.attested() {
        info
    } else {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    };

    let bytes = attest.marshall()?;

    let hash_alg = match (public, signature) {
        #[cfg(any(feature = "p224", feature = "p256", feature = "p384"))]
        (Public::Ecc { parameters, .. }, _) => {
            let mut hash_alg = None;
            macro_rules! impl_check_ecdsa {
                ($curve: ty) => {
                    if parameters.ecc_curve() == <$curve>::TPM_CURVE {
                        let Signature::EcDsa(sig) = signature else {
                            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
                        };
                        if !verify_ecdsa::<$curve>(&public, &bytes, &sig, sig.hashing_algorithm())?
                        {
                            return Ok(false);
                        }
                        hash_alg = Some(sig.hashing_algorithm());
                    }
                };
            }
            #[cfg(feature = "p224")]
            impl_check_ecdsa!(p224::NistP224);
            #[cfg(feature = "p256")]
            impl_check_ecdsa!(p256::NistP256);
            #[cfg(feature = "p384")]
            impl_check_ecdsa!(p384::NistP384);

            if let Some(h) = hash_alg {
                h
            } else {
                return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
            }
        }
        #[cfg(feature = "rsa")]
        (Public::Rsa { .. }, sig @ Signature::RsaSsa(pkcs_sig)) => {
            let Ok(sig) = pkcs1v15::Signature::try_from(sig) else {
                return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
            };

            if !verify_rsa_pkcs1v15(public, &bytes, &sig, pkcs_sig.hashing_algorithm())? {
                return Ok(false);
            }
            pkcs_sig.hashing_algorithm()
        }
        #[cfg(feature = "rsa")]
        (Public::Rsa { .. }, sig @ Signature::RsaPss(pkcs_sig)) => {
            let Ok(sig) = pss::Signature::try_from(sig) else {
                return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
            };

            if !verify_rsa_pss(public, &bytes, &sig, pkcs_sig.hashing_algorithm())? {
                return Ok(false);
            }
            pkcs_sig.hashing_algorithm()
        }
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };

    if qualifying_data != attest.extra_data().as_bytes() {
        return Ok(false);
    }
    if let Some((selections, digests)) = pcr_data {
        if !checkquote_pcr_digests(quote, selections, digests, hash_alg)? {
            return Ok(false);
        }
    }
    Ok(true)
}
