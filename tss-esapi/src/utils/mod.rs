// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Utility module
//!
//! This module mostly contains helper elements meant to act as either wrappers around FFI-level
//! structs or builders for them, along with other convenience elements.
//! The naming structure usually takes the names inherited from the TSS spec and applies Rust
//! guidelines to them. Structures that are meant to act as builders have `Builder` appended to
//! type name. Unions are converted to Rust `enum`s by dropping the `TPMU` qualifier and appending
//! `Union`.
use crate::attributes::ObjectAttributesBuilder;
use crate::constants::PropertyTag;
use crate::interface_types::{
    algorithm::{HashingAlgorithm, PublicAlgorithm},
    ecc::EccCurve,
    key_bits::RsaKeyBits,
};
use crate::structures::{
    EccPoint, EccScheme, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
};
use crate::{Context, Error, Result, WrapperErrorKind};
use std::convert::TryFrom;
use zeroize::Zeroize;

#[cfg(feature = "rustcrypto")]
use {
    crate::traits::Marshall,
    core::marker::PhantomData,
    digest::{crypto_common::KeySizeUser, Digest, OutputSizeUser},
};

#[cfg(feature = "rustcrypto")]
mod credential;
#[cfg(feature = "rustcrypto")]
mod duplication;
#[cfg(feature = "rustcrypto")]
pub mod kdf;
#[cfg(feature = "rustcrypto")]
mod secret_sharing;

#[cfg(all(feature = "rustcrypto", feature = "rsa"))]
pub use self::credential::make_credential_rsa;
#[cfg(feature = "rustcrypto")]
pub use self::{
    credential::make_credential_ecc,
    duplication::{create_duplicate, DuplicatePayload},
};

/// Create the [Public] structure for a restricted decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_restricted_decryption_rsa_public(
    symmetric: SymmetricDefinitionObject,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_restricted_decryption_key(
                symmetric,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an unrestricted encryption/decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_unrestricted_encryption_decryption_rsa_public(
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_scheme(RsaScheme::Null)
                .with_key_bits(rsa_key_bits)
                .with_exponent(rsa_pub_exponent)
                .with_is_signing_key(true)
                .with_is_decryption_key(true)
                .with_restricted(false)
                .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an RSA unrestricted signing key.
///
/// * `scheme` - RSA scheme to be used for signing
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
pub fn create_unrestricted_signing_rsa_public(
    scheme: RsaScheme,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_unrestricted_signing_key(
                scheme,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
}

/// Create the [Public] structure for an RSA unrestricted signing key.
///
/// * `scheme` - RSA scheme to be used for signing
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key
/// * `rsa_public_key` - The public part of the RSA key that is going to be used as unique identifier.
pub fn create_unrestricted_signing_rsa_public_with_unique(
    scheme: RsaScheme,
    rsa_key_bits: RsaKeyBits,
    rsa_pub_exponent: RsaExponent,
    rsa_public_key: PublicKeyRsa,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new_unrestricted_signing_key(
                scheme,
                rsa_key_bits,
                rsa_pub_exponent,
            )
            .build()?,
        )
        .with_rsa_unique_identifier(rsa_public_key)
        .build()
}

/// Create the [Public] structure for an ECC unrestricted signing key.
///
/// * `scheme` - Asymmetric scheme to be used for signing; *must* be an RSA signing scheme
/// * `curve` - identifier of the precise curve to be used with the key
pub fn create_unrestricted_signing_ecc_public(
    scheme: EccScheme,
    curve: EccCurve,
) -> Result<Public> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, curve).build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Container for public key values
///
/// # Details
/// This object can be serialized and deserialized
/// using serde if the `serde` feature is enabled.
#[derive(Debug, Clone, Zeroize, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum PublicKey {
    /// RSA public modulus (see 27.5.3.4 in the Architecture spec)
    ///
    /// This is the value extracted from the `unique` part of `TPMT_PUBLIC`.
    /// The exponent is not included here as the expectation is that the
    /// exponent is always pinned to 65537 (2^16 + 1).
    ///
    /// The modulus is in Big-Endian format.
    Rsa(Vec<u8>),
    /// Public elliptic curve point (see 27.5.3.5 in the Architecture spec)
    ///
    /// The x and y coordinates are given uncompressed.
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

impl TryFrom<Public> for PublicKey {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        match public {
            Public::Rsa { unique, .. } => Ok(PublicKey::Rsa(unique.as_bytes().to_vec())),
            Public::Ecc { unique, .. } => Ok(PublicKey::Ecc {
                x: unique.x().as_bytes().to_vec(),
                y: unique.y().as_bytes().to_vec(),
            }),
            _ => Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
        }
    }
}

fn tpm_int_to_string(num: u32) -> String {
    num.to_be_bytes()
        .iter()
        .filter(|x| **x != 0)
        .map(|x| char::from(*x))
        .collect()
}

/// Get the TPM vendor name
pub fn get_tpm_vendor(context: &mut Context) -> Result<String> {
    // Retrieve the TPM property values
    Ok([
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ]
    .iter()
    // Retrieve property values
    .map(|prop_id| context.get_tpm_property(*prop_id))
    // Collect and return an error if we got one
    .collect::<Result<Vec<Option<u32>>>>()?
    .iter()
    // Filter out the Option::None values
    .filter_map(|x| *x)
    // Filter out zero values
    .filter(|x| *x != 0)
    // Map through int_to_string
    .map(tpm_int_to_string)
    // Collect to a single string
    .collect())
}

/// Hash an object into a [`Digest`]
#[cfg(feature = "rustcrypto")]
pub(crate) fn hash_object<D, T>(hasher: &mut D, object: &T) -> Result<()>
where
    D: Digest,
    T: Marshall,
{
    let buf = object.marshall()?;
    hasher.update(buf);

    //const BUF_SIZE: usize = 128;
    //let mut buf = [0u8; BUF_SIZE];
    //let mut offset = 0;

    //// TODO: BUFFER_SIZE is a max, we shall stop if offset didn't bodge
    //while offset < T::BUFFER_SIZE {
    //    let remaining = T::BUFFER_SIZE - offset;
    //    let buf = &mut buf[..BUF_SIZE.min(remaining)];

    //    object.marshall_offset(buf, &mut offset)?;
    //    hasher.update(buf);
    //}

    Ok(())
}

/// Helper macro to match on the name_hashing_algorithm of a public object
///
/// ```ignore
/// macro_rules! match_inner {
///     ($hash: ty) => {
///         inner_wrapper_hash::<R, PSymAlg, $hash>(rng, sensitive_kp)
///     };
/// }
///
/// match_name_hashing_algorithm!(sensitive_pub, match_inner);
/// ```
macro_rules! match_name_hashing_algorithm {
    ($pub_object: expr, $inner: ident) => {{
        use crate::{
            error::{Error, WrapperErrorKind},
            interface_types::algorithm::HashingAlgorithm,
        };
        match $pub_object.name_hashing_algorithm() {
            HashingAlgorithm::Null => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
            #[cfg(feature = "sha1")]
            HashingAlgorithm::Sha1 => $inner!(sha1::Sha1),
            #[cfg(feature = "sha2")]
            HashingAlgorithm::Sha256 => $inner!(sha2::Sha256),
            #[cfg(feature = "sha2")]
            HashingAlgorithm::Sha384 => $inner!(sha2::Sha384),
            #[cfg(feature = "sha2")]
            HashingAlgorithm::Sha512 => $inner!(sha2::Sha512),
            #[cfg(feature = "sha3")]
            HashingAlgorithm::Sha3_256 => $inner!(sha3::Sha3_256),
            #[cfg(feature = "sha3")]
            HashingAlgorithm::Sha3_384 => $inner!(sha3::Sha3_384),
            #[cfg(feature = "sha3")]
            HashingAlgorithm::Sha3_512 => $inner!(sha3::Sha3_512),
            #[cfg(feature = "sm3")]
            HashingAlgorithm::Sm3_256 => $inner!(sm3::Sm3),
            #[cfg(not(all(
                feature = "sha1",
                feature = "sha2",
                feature = "sha3",
                feature = "sm3",
            )))]
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }};
}

// Ensure we can use the macro elsewhere in the crate
pub(crate) use match_name_hashing_algorithm;

// [`TpmHmac`] intends to code for the key expected for hmac
// in the KDFa and KDFe derivations. There are no standard sizes for hmac keys really,
// upstream RustCrypto considers it to be [BlockSize], but TPM specification
// has a different opinion on the matter, and expect the key to the output
// bit size of the hash algorithm used.
//
// See https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=202
// section 24.5 HMAC:
//   bits the number of bits in the digest produced by ekNameAlg
//
// [BlockSize]: https://docs.rs/hmac/0.12.1/hmac/struct.HmacCore.html#impl-KeySizeUser-for-HmacCore%3CD%3E
#[cfg(feature = "rustcrypto")]
pub(super) struct TpmHmac<H>(PhantomData<H>);

#[cfg(feature = "rustcrypto")]
impl<H> KeySizeUser for TpmHmac<H>
where
    H: OutputSizeUser,
{
    type KeySize = H::OutputSize;
}
