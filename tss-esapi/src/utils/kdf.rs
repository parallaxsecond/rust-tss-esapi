// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use core::ops::Mul;

use byte_strings::concat_bytes;
use digest::{
    array::ArraySize, common::KeySizeUser, consts::U8, typenum::Unsigned, Digest, FixedOutputReset,
    Key, OutputSizeUser,
};
use ecdsa::elliptic_curve::{
    ecdh::SharedSecret,
    point::AffineCoordinates,
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey,
};
use hmac::{EagerHash, Hmac};
use kbkdf::{Counter, Kbkdf, Params};
use log::error;

use crate::{Error, Result, WrapperErrorKind};

/// Label to be applied when deriving a key with either [`kdfa`] or [`kdfe`]
pub trait KdfLabel {
    /// Label that should be used for a given application
    const LABEL: &[u8];
    /// Label for a given application encoded as C string (terminated with `\0`].
    const C_LABEL: &[u8];
}

macro_rules! impl_kdf_label {
    ($usage:ty, $value: expr) => {
        impl KdfLabel for $usage {
            const LABEL: &[u8] = $value;
            const C_LABEL: &[u8] = concat_bytes!($value, b"\0");
        }
    };
}

#[derive(Copy, Clone, Debug)]
pub struct Secret;
impl_kdf_label!(Secret, b"SECRET");

#[derive(Copy, Clone, Debug)]
pub struct Context;
impl_kdf_label!(Context, b"CONTEXT");

#[derive(Copy, Clone, Debug)]
pub struct Obfuscate;
impl_kdf_label!(Obfuscate, b"OBFUSCATE");

#[derive(Copy, Clone, Debug)]
pub struct Storage;
impl_kdf_label!(Storage, b"STORAGE");

#[derive(Copy, Clone, Debug)]
pub struct Integrity;
impl_kdf_label!(Integrity, b"INTEGRITY");

#[derive(Copy, Clone, Debug)]
pub struct Commit;
impl_kdf_label!(Commit, b"COMMIT");

#[derive(Copy, Clone, Debug)]
pub struct Cfb;
impl_kdf_label!(Cfb, b"CFB");

#[derive(Copy, Clone, Debug)]
pub struct Xor;
impl_kdf_label!(Xor, b"XOR");

#[derive(Copy, Clone, Debug)]
pub struct Session;
impl_kdf_label!(Session, b"SESSION");

#[derive(Copy, Clone, Debug)]
pub struct Identity;
impl_kdf_label!(Identity, b"IDENTITY");

/// KDFa
///
/// This is a counter mode KDF from SP 800-108. It uses HMAC as the pseudo-random function (PRF). It is referred
/// to in the [specification as `KDFa()`, defined in Section 9.4.10.2 KDFa()].
///
/// [specification as `KDFa()`, defined in Section 9.4.10.2 KDFa()]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=50
///
/// # Parameters
///
///  - Type parameters:
///    - `HashAlg` is the [`Digest`] to be used,
///    - `Label` is the indicated use of the key eg: [`Context`], [`Storage`], [`Integrity`], ...
///    - `K` is the number of of **bytes** in the output key,
///      Note: Spec calls for **bits** but we have no support for partial bytes,
///
///  - Parameters:
///    - `key` is a variable-sized value use as Kin,
///    - `context_u` (`contextU` in the spec), is a variable-sized value concatenated with `context_v`
///      to create the `Context` parameter used of the Counter mode KDF,
///    - `context_v` (`contextV` in the spec), is a variable-sized value concatenated with
///      `context_u` (see above).
///
/// # Usage
///
/// ```ignore
/// // KDFa(sha256, key, "STORAGE", contextU, contextV, 256)
/// kdfa::<Sha256, Storage, Key<Aes256>>(key, contextU, contextV);
/// ```
// TODO: Support generation of non-complete bytes:
// See:
// ```
// If KDFa() were used to produce a 521-bit ECC private key, the returned value would occupy 66 octets, with
// the upper 7 bits of the octet at offset zero set to 0.
// ```
// https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=51
pub fn kdfa<HashAlg, Label, K>(key: &[u8], context_u: &[u8], context_v: &[u8]) -> Result<Key<K>>
where
    Label: KdfLabel,

    HashAlg: EagerHash,
    K: KeySizeUser,

    K::KeySize: ArraySize + Mul<U8>,
    <K::KeySize as Mul<U8>>::Output: Unsigned,

    <<HashAlg as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
    <<<HashAlg as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,
{
    let mut context = Vec::with_capacity(context_u.len() + context_v.len());
    context.extend_from_slice(context_u);
    context.extend_from_slice(context_v);

    let kdf = Counter::<Hmac<HashAlg>, K>::default();
    kdf.derive(
        Params::builder(key)
            .with_label(Label::LABEL)
            .with_context(&context)
            .build(),
    )
    .map_err(|e| {
        error!("KDFa derivation error: {e}");
        Error::local_error(WrapperErrorKind::InternalError)
    })
}

/// KDFe for ECDH
///
/// This provides a symmetric encryption key for an ECC-protected object. It is defined in
/// [Section 9.4.10.3 KDFe for ECDH] of the spec
///
/// [Section 9.4.10.3 KDFe for ECDH]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=52
///
/// # Parameters
///
///  - Type parameters:
///    - `Use` is the indicated use of the key eg: [`Context`], [`Storage`], [`Integrity`], ...
///    - `HashAlg` is the [`Digest`] to be used,
///    - `C` is the [`Curve`] used by the ECC key,
///    - `K` is the number of of **bytes** in the output key,
///      Note: Spec calls for **bits** but we have no support for partial bytes,
///
///  - Parameters:
///    - `z` (`Z` in the spec) is the product of a public point and a private x coordinate. This will be an ECDH
///      [`SharedSecret`] on the curve (`C`),
///    - `party_u_info` (`PartyUInfo` in the spec), is the public point of the ephemeral used to
///      compute `Z`,
///    - `party_v_info` (`PartyVInfo` in the spec), is the public point of a static TPM key
pub fn kdfe<Use, HashAlg, C, K>(
    z: &SharedSecret<C>,
    party_u_info: &PublicKey<C>,
    party_v_info: &PublicKey<C>,
) -> Result<Key<K>>
where
    Use: KdfLabel,

    HashAlg: Digest + FixedOutputReset,
    C: Curve + CurveArithmetic,
    K: KeySizeUser,

    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let mut key = Key::<K>::default();

    let label_size = Use::C_LABEL.len();
    let mut other_info = vec![0; label_size + (2 * FieldBytesSize::<C>::USIZE)];
    other_info[..label_size].copy_from_slice(Use::C_LABEL);
    other_info[label_size..label_size + FieldBytesSize::<C>::USIZE]
        .copy_from_slice(&party_u_info.as_affine().x());
    other_info[label_size + FieldBytesSize::<C>::USIZE..]
        .copy_from_slice(&party_v_info.as_affine().x());

    one_step_kdf::derive_key_into::<HashAlg>(z.raw_secret_bytes(), &other_info, &mut key).map_err(
        |e| {
            error!("KDFe derivation error: {e}");
            Error::local_error(WrapperErrorKind::InternalError)
        },
    )?;

    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    use aes::Aes256;
    use cipher::Array;
    use hex_literal::hex;
    use sha2::Sha256;

    #[test]
    fn test_kdfe() {
        struct Vector<const S: usize, const K: usize, const E: usize> {
            shared_secret: [u8; S],
            local_key: [u8; K],
            remote_key: [u8; K],
            expected: [u8; E],
        }

        // Test vectors here were manually generated from tpm2-pytss
        static TEST_VECTORS_SHA256: [Vector<
            { FieldBytesSize::<p256::NistP256>::USIZE },
            { <FieldBytesSize<p256::NistP256> as ModulusSize>::CompressedPointSize::USIZE },
            32,
        >; 2] = [
            Vector {
                shared_secret: hex!(
                    "c75afb6f49c941ef194b232d7615769f5152d20de5dee19a991067f337dd65bc"
                ),
                local_key: hex!(
                    "031ba4030de068a2f07919c42ef6b19f302884f35f45e7d4e4bb90ffbb0bd9d099"
                ),
                remote_key: hex!(
                    "038f2b219a29c2ff9ba69cedff2d08d33a5dbca3da6bc8af8acd3ff6f5ec4dfbef"
                ),
                expected: hex!("e3a0079db19724f9b76101e9364c4a149cea3501336abc3b603f94b22b6309a5"),
            },
            Vector {
                shared_secret: hex!(
                    "a90a1c095155428500ed19e87c0df078df3dd2e66a0e3bbe664ba9ff62113b4a"
                ),
                local_key: hex!(
                    "03e9c7d6a853ba6176b65ec2f328bdea25f61c4e1b23a4e1c08e1da8c723381a04"
                ),
                remote_key: hex!(
                    "036ccf059628d3cdf8e1b4c4ba6d14696ba51cc8d4a96df4016f0b214782d5cee6"
                ),
                expected: hex!("865f8093e2c4b801dc8c236eeb2806c7b1c51c2cb04101c035f7f2511ea0aeda"),
            },
        ];

        for v in &TEST_VECTORS_SHA256 {
            let out = kdfe::<Identity, Sha256, p256::NistP256, Aes256>(
                &SharedSecret::from(Array::from(v.shared_secret)),
                &PublicKey::try_from(Array::from(v.local_key)).unwrap(),
                &PublicKey::try_from(Array::from(v.remote_key)).unwrap(),
            )
            .unwrap();
            assert_eq!(out, v.expected);
        }
    }

    #[test]
    fn test_kdfa() {
        struct Vector {
            key: &'static [u8],
            context_u: &'static [u8],
            context_v: &'static [u8],
            expected: &'static [u8],
        }

        static TEST_VECTORS_SHA256: [Vector; 1] = [Vector {
            key: &hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            context_u: b"",
            context_v: &hex!("0506070809"),
            expected: &hex!("de275f7f5cfeaac226b30d42377903b34705f178730d96400ccafb736e3d28a4"),
        }];

        for v in &TEST_VECTORS_SHA256 {
            let out = kdfa::<Sha256, Storage, Aes256>(v.key, v.context_u, v.context_v).unwrap();
            assert_eq!(out.as_slice(), v.expected);
        }
    }
}
