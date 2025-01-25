// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use core::ops::{Add, Mul};

use cfb_mode::cipher::{AsyncStreamCipher, BlockCipherEncrypt};
use digest::{
    array::ArraySize,
    consts::{B1, U8},
    crypto_common::{Iv, KeyIvInit, KeySizeUser, WeakKeyError},
    typenum::{
        operator_aliases::{Add1, Sum},
        Unsigned,
    },
    Digest, FixedOutputReset, Key, KeyInit, Mac, OutputSizeUser,
};
use ecdsa::elliptic_curve::{
    sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, PublicKey,
};
use hmac::{EagerHash, Hmac};
use log::error;
use rand::rng;
use zeroize::Zeroizing;

#[cfg(feature = "rsa")]
use rsa::RsaPublicKey;

use crate::{
    error::{Error, Result, WrapperErrorKind},
    structures::{EncryptedSecret, IdObject, Name},
    utils::{kdf, secret_sharing, TpmHmac},
};

type WeakResult<T> = core::result::Result<T, WeakKeyError>;

/// [`make_credential_ecc`] creates a credential that will only be decrypted by the target
/// elliptic-curve EK.
///
/// # Parameters
///
/// * `ek_public` is the EC Public key of the Endorsement Key,
/// * `secret` is the serialization of the credential,
/// * `name` will usually be the AK held on the TPM.
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

    EkHash: Digest + FixedOutputReset + EagerHash,
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
        let (seed, encrypted_secret) = secret_sharing::secret_sharing_ecc_curve::<
            _,
            kdf::Identity,
            C,
            TpmHmac<EkHash>,
            EkHash,
        >(&mut rng, &ek_public)?;

        match secret_to_credential::<EkHash, EkCipher>(&seed, secret, &key_name)? {
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

/// [`make_credential_rsa`] creates a credential that will only be decrypted by the target RSA EK.
///
/// # Parameters
///
/// * `ek_public` is the RSA Public key of the Endorsement Key,
/// * `secret` is the serialization of the credential,
/// * `name` will usually be the AK held on the TPM.
#[cfg(feature = "rsa")]
pub fn make_credential_rsa<EkHash, EkCipher>(
    ek_public: &RsaPublicKey,
    secret: &[u8],
    key_name: Name,
) -> Result<(IdObject, EncryptedSecret)>
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
    let mut rng = rng();

    loop {
        let (random_seed, encrypted_secret) =
            secret_sharing::secret_sharing_rsa::<_, kdf::Identity, TpmHmac<EkHash>, EkHash>(
                &mut rng, ek_public,
            )?;

        match secret_to_credential::<EkHash, EkCipher>(&random_seed, secret, &key_name)? {
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
    seed: &Key<TpmHmac<EkHash>>,
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
    let mut sensitive_data = {
        let mut out = Zeroizing::new(vec![]);
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
    let sym_key = kdf::kdfa::<EkHash, kdf::Storage, EkCipher>(seed, key_name.value(), &[])?;

    if EkCipher::weak_key_test(&sym_key).is_err() {
        // 11.4.10.4 Rejection of weak keys
        // https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82
        // The Key was considered weak, and we should re-run the creation of the encrypted
        // secret.

        return Ok(Err(WeakKeyError));
    }

    let iv: Iv<cfb_mode::Encryptor<EkCipher>> = Default::default();

    cfb_mode::Encryptor::<EkCipher>::new(&sym_key, &iv).encrypt(&mut sensitive_data);

    // See 24.5 HMAC
    let hmac_key = kdf::kdfa::<EkHash, kdf::Integrity, TpmHmac<EkHash>>(seed, &[], &[])?;
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
