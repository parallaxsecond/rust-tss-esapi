// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use core::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use cfb_mode::cipher::{AsyncStreamCipher, BlockCipherEncrypt};
use digest::{
    array::ArraySize,
    consts::{B1, U8},
    crypto_common::{Iv, KeyIvInit, KeySizeUser, WeakKeyError},
    typenum::{
        operator_aliases::{Add1, Sum},
        Unsigned,
    },
    Digest, DynDigest, FixedOutputReset, Key, KeyInit, Mac, OutputSizeUser,
};
use ecdsa::elliptic_curve::{
    ecdh::{EphemeralSecret, SharedSecret},
    sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey,
};
use hmac::{EagerHash, Hmac};
use log::error;
use rand::{rng, Rng};
use rsa::{Oaep, RsaPublicKey};

use crate::{
    error::{Error, Result, WrapperErrorKind},
    structures::{EncryptedSecret, IdObject, Name},
    utils::kdf::{self},
};

type WeakResult<T> = core::result::Result<T, WeakKeyError>;

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
struct TpmHmac<H>(PhantomData<H>);

impl<H> KeySizeUser for TpmHmac<H>
where
    H: OutputSizeUser,
{
    type KeySize = H::OutputSize;
}

pub fn make_credential_ecc<C, EkHash, EkCipher>(
    ek_public: PublicKey<C>,
    secret: &[u8],
    key_name: Name,
) -> Result<(IdObject, EncryptedSecret)>
where
    C: Curve + CurveArithmetic,

    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,

    <FieldBytesSize<C> as Add>::Output: Add<FieldBytesSize<C>>,
    Sum<FieldBytesSize<C>, FieldBytesSize<C>>: ArraySize,
    Sum<FieldBytesSize<C>, FieldBytesSize<C>>: Add<U8>,
    Sum<Sum<FieldBytesSize<C>, FieldBytesSize<C>>, U8>: Add<B1>,
    Add1<Sum<Sum<FieldBytesSize<C>, FieldBytesSize<C>>, U8>>: ArraySize,

    EkHash: Digest + EagerHash + FixedOutputReset,
    <EkHash as OutputSizeUser>::OutputSize: Mul<U8>,
    <<EkHash as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,
    <<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
    <<<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit,
    <EkCipher as KeySizeUser>::KeySize: Mul<U8>,
    <<EkCipher as KeySizeUser>::KeySize as Mul<U8>>::Output: ArraySize,
{
    let mut rng = rng();

    loop {
        // See Table 22 - Key Generation for the various labels used here after:
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=183

        // C.6.4. ECC Secret Sharing for Credentials
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=311
        let local = EphemeralSecret::<C>::random(&mut rng);

        let ecdh_secret: SharedSecret<C> = local.diffie_hellman(&ek_public);
        let local_public = local.public_key();
        drop(local);

        let seed = kdf::kdfe::<kdf::Identity, EkHash, C, TpmHmac<EkHash>>(
            &ecdh_secret,
            &local_public,
            &ek_public,
        )?;
        drop(ecdh_secret);

        // The local ECDH pair is used as "encrypted seed"
        let encoded_point = local_public.to_encoded_point(false);
        let Coordinates::Uncompressed {
            x: point_x,
            y: point_y,
        } = encoded_point.coordinates()
        else {
            // NOTE: The only way this could trigger would be for the local key to be identity.
            error!("Couldn't compute coordinates for the local public key");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        };
        let encrypted_seed = {
            let mut out = vec![];
            out.extend_from_slice(&FieldBytesSize::<C>::U16.to_be_bytes()[..]);
            out.extend_from_slice(point_x);
            out.extend_from_slice(&FieldBytesSize::<C>::U16.to_be_bytes()[..]);
            out.extend_from_slice(point_y);
            out
        };
        let encrypted_secret = EncryptedSecret::from_bytes(&encrypted_seed)?;

        match secret_to_credential::<EkHash, EkCipher>(seed, secret, &key_name)? {
            Ok(id_object) => return Ok((id_object, encrypted_secret)),
            Err(WeakKeyError) => {
                // 11.4.10.4 Rejection of weak keys
                // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82

                // The Key was considered weak, and we should re-run the creation of the encrypted
                // secret.
                continue;
            }
        }
    }
}

pub fn make_credential_rsa<EkHash, EkCipher>(
    ek_public: &RsaPublicKey,
    secret: &[u8],
    key_name: Name,
) -> Result<(IdObject, EncryptedSecret)>
where
    EkHash: Digest + DynDigest + Send + Sync + 'static,
    EkHash: EagerHash + FixedOutputReset,
    <EkHash as OutputSizeUser>::OutputSize: Mul<U8>,
    <<EkHash as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,
    <<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
    <<<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit,
    <EkCipher as KeySizeUser>::KeySize: Mul<U8>,
    <<EkCipher as KeySizeUser>::KeySize as Mul<U8>>::Output: ArraySize,
{
    let mut rng = rng();

    loop {
        // See Table 22 - Key Generation for the various labels used here after:
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=183

        // B.10.4 RSA Secret Sharing for Credentials
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=302
        let random_seed = {
            let mut out = Key::<TpmHmac<EkHash>>::default();
            rng.fill(out.as_mut_slice());
            out
        };

        // The random seed is then encrypted with RSA-OAEP
        //
        // B.4 RSAES_OAEP
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=297
        //
        // The label is a byte-stream whose last byte must be zero
        //
        // B.10.4. RSA Secret Sharing for Credentials
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=302
        //
        // The label is going to be "IDENTITY" for secret sharing.
        let encrypted_seed = {
            let padding = Oaep::new_with_label::<EkHash, _>(b"IDENTITY\0".to_vec());
            ek_public
                .encrypt(&mut rng, padding, &random_seed[..])
                .map_err(|e| {
                    error!("RSA OAEP encryption error: {e}");
                    Error::local_error(WrapperErrorKind::InternalError)
                })?
        };
        let encrypted_secret = EncryptedSecret::from_bytes(&encrypted_seed)?;

        match secret_to_credential::<EkHash, EkCipher>(random_seed, secret, &key_name)? {
            Ok(id_object) => return Ok((id_object, encrypted_secret)),
            Err(WeakKeyError) => {
                // 11.4.10.4 Rejection of weak keys
                // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82

                // The Key was considered weak, and we should re-run the creation of the encrypted
                // secret.
                continue;
            }
        }
    }
}

fn secret_to_credential<EkHash, EkCipher>(
    seed: Key<TpmHmac<EkHash>>,
    secret: &[u8],
    key_name: &Name,
) -> Result<WeakResult<IdObject>>
where
    EkHash: Digest + EagerHash + FixedOutputReset,
    <EkHash as OutputSizeUser>::OutputSize: Mul<U8>,
    <<EkHash as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,
    <<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
    <<<EkHash as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit,
    <EkCipher as KeySizeUser>::KeySize: Mul<U8>,
    <<EkCipher as KeySizeUser>::KeySize as Mul<U8>>::Output: ArraySize,
{
    // Prepare the sensitive data
    // this will be then encrypted using AES-CFB (size of the symmetric key depends on the EK).
    // NOTE(security): no need to zeroize it, content is rewritten in place with the encrypted version
    let mut sensitive_data = {
        let mut out = vec![];
        out.extend_from_slice(
            &u16::try_from(secret.len())
                .map_err(|_| {
                    error!("secret may only be 2^16 bytes long");
                    Error::local_error(WrapperErrorKind::WrongParamSize)
                })?
                .to_be_bytes()[..],
        );
        out.extend_from_slice(secret);
        out
    };

    // We'll now encrypt the sensitive data, and hmac the result of the encryption
    // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=201
    // See 24.4 Symmetric Encryption
    let sym_key = kdf::kdfa::<EkHash, kdf::Storage, EkCipher>(&seed, key_name.value(), &[])?;

    if EkCipher::weak_key_test(&sym_key).is_ok() {
        // 11.4.10.4 Rejection of weak keys
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82
        // The Key was considered weak, and we should re-run the creation of the encrypted
        // secret.

        return Ok(Err(WeakKeyError));
    }

    let iv: Iv<cfb_mode::Encryptor<EkCipher>> = Default::default();

    cfb_mode::Encryptor::<EkCipher>::new(&sym_key, &iv).encrypt(&mut sensitive_data);

    // See 24.5 HMAC
    let hmac_key = kdf::kdfa::<EkHash, kdf::Integrity, TpmHmac<EkHash>>(&seed, &[], &[])?;
    let mut hmac = Hmac::<EkHash>::new_from_slice(&hmac_key).map_err(|e| {
        error!("HMAC initialization error: {e}");
        Error::local_error(WrapperErrorKind::WrongParamSize)
    })?;
    Mac::update(&mut hmac, &sensitive_data);
    Mac::update(&mut hmac, key_name.value());
    let hmac = hmac.finalize();

    // We'll now serialize the object and get everything through the door.
    let mut out = vec![];
    out.extend_from_slice(
        &u16::try_from(hmac.into_bytes().len())
            .map_err(|_| {
                // NOTE: this shouldn't ever trigger ... but ...
                error!("HMAC output may only be 2^16 bytes long");
                Error::local_error(WrapperErrorKind::WrongParamSize)
            })?
            .to_be_bytes()[..],
    );
    out.extend_from_slice(&hmac.into_bytes());
    out.extend_from_slice(&sensitive_data);

    IdObject::from_bytes(&out).map(Ok)
}
