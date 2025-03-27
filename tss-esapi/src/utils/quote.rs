// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::error::Error;
use crate::error::Result;
use crate::WrapperErrorKind;
use crate::{
    interface_types::algorithm::HashingAlgorithm,
    structures::{Attest, AttestInfo, DigestList, PcrSelectionList, Public, QuoteInfo, Signature},
    traits::Marshall,
    utils::PublicKey,
};
use digest::{Digest, DynDigest};

#[cfg(feature = "p256")]
use crate::structures::EccSignature;
#[cfg(feature = "p256")]
use p256::ecdsa::{Signature as SignatureP256, VerifyingKey};
#[cfg(feature = "p256")]
use signature::{hazmat::PrehashVerifier, Verifier};

#[cfg(feature = "rsa")]
use crate::structures::RsaSignature;
#[cfg(feature = "rsa")]
use rsa::{pss::Pss, RsaPublicKey};

#[cfg(feature = "p256")]
fn verify_p256(public: &Public, message: &[u8], signature: &EccSignature) -> Result<bool> {
    let public_key = PublicKey::try_from(public.clone())?;
    let (x, y) = match public_key {
        PublicKey::Ecc { x, y } => (x, y),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
    };
    let mut sec1_bytes = Vec::<u8>::with_capacity(1 + x.len() + y.len());
    sec1_bytes.push(0x04);
    sec1_bytes.extend_from_slice(&x);
    sec1_bytes.extend_from_slice(&y);
    let verifying_key = match VerifyingKey::from_sec1_bytes(&sec1_bytes) {
        Ok(s) => s,
        Err(_) => {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
    };

    let mut sig_bytes = Vec::with_capacity(64);
    sig_bytes.extend_from_slice(signature.signature_r().as_ref());
    sig_bytes.extend_from_slice(signature.signature_s().as_ref());
    let generic_sig = digest::generic_array::GenericArray::clone_from_slice(&sig_bytes);
    let sig = match SignatureP256::from_bytes(&generic_sig) {
        Ok(s) => s,
        Err(_) => {
            return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
        }
    };

    let verify_result = match signature.hashing_algorithm() {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            Digest::update(&mut hasher, &message);
            verifying_key.verify_prehash(&hasher.finalize(), &sig)
        }
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => verifying_key.verify(&message, &sig),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };
    return Ok(match verify_result {
        Ok(_) => true,
        Err(_) => false,
    });
}

#[cfg(feature = "rsa")]
fn verify_rsa(public: &Public, message: &[u8], signature: &RsaSignature) -> Result<bool> {
    let public_key = PublicKey::try_from(public.clone())?;
    let rsa_key = RsaPublicKey::try_from(&public_key)?;
    let sig = signature.signature();
    let mut hasher: Box<dyn DynDigest> = match signature.hashing_algorithm() {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => Box::new(sha1::Sha1::new()),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => Box::new(sha2::Sha256::new()),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };
    hasher.update(&message);
    let hash = hasher.finalize().to_vec();

    let scheme = match signature.hashing_algorithm() {
        #[cfg(feature = "sha1")]
        HashingAlgorithm::Sha1 => Pss::new::<sha1::Sha1>(),
        #[cfg(feature = "sha2")]
        HashingAlgorithm::Sha256 => Pss::new::<sha2::Sha256>(),
        _ => {
            return Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam));
        }
    };
    return Ok(match rsa_key.verify(scheme, &hash, &sig) {
        Ok(_) => true,
        Err(_) => false,
    });
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
/// #     abstraction::{ak, ek, AsymmetricAlgorithmSelection},
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
/// #     utils,
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
/// utils::checkquote(
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
    let hash_alg = match signature {
        #[cfg(feature = "p256")]
        Signature::EcDsa(sig) => {
            if !verify_p256(&public, &bytes, &sig)? {
                return Ok(false);
            }
            sig.hashing_algorithm()
        }
        #[cfg(feature = "rsa")]
        Signature::RsaPss(sig) => {
            if !verify_rsa(&public, &bytes, &sig)? {
                return Ok(false);
            }
            sig.hashing_algorithm()
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
