// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use core::{
    fmt,
    ops::{Add, Mul},
};

use cfb_mode::cipher::BlockCipherEncrypt;
use digest::{
    array::ArraySize,
    common::{Iv, KeyIvInit, KeySizeUser},
    consts::{B1, U8},
    typenum::{
        operator_aliases::{Add1, Sum},
        Unsigned,
    },
    Digest, FixedOutputReset, Key, KeyInit, Mac, OutputSizeUser,
};
use ecdsa::elliptic_curve::{
    sec1::{FromSec1Point, ModulusSize, ToSec1Point},
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

/// Test if a key is considered weak according to TCG.
///
/// TCG will require weak keys to be re-generated,  
/// See:
/// ```text
/// 11.4.10.4 Rejection of weak keys
/// https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82
/// The Key was considered weak, and we should re-run the creation of the encrypted
/// secret.
/// ```
pub trait TcgKeyTest: KeyInit {
    fn tcg_weak_key_test(key: &Key<Self>) -> core::result::Result<(), WeakKeyError>;
}

/// The error type returned when a key is found to be weak.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct WeakKeyError;

impl fmt::Display for WeakKeyError {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WeakKey")
    }
}

impl core::error::Error for WeakKeyError {}

type WeakResult<T> = core::result::Result<T, WeakKeyError>;

#[cfg(feature = "aes")]
mod key_test_aes {
    use cipher::{typenum::Unsigned, Key, KeySizeUser};
    use elliptic_curve::subtle::{Choice, ConstantTimeGreater};

    use super::{TcgKeyTest, WeakKeyError};

    macro_rules! weak_key_test {
        ($k: ty) => {
            impl TcgKeyTest for $k {
                fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
                    // Check if any bit of the upper half of the key is set
                    //
                    // This follows the in terpretation laid out in section `11.4.10.4 Reject of weak keys`
                    // from the TPM specification:
                    // ```
                    // In the case of AES, at least one bit in the upper half of the key must be set
                    // ```
                    // See: https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-1-Architecture.pdf#page=82
                    let mut weak = Choice::from(0);

                    for v in &key[..(<<$k as KeySizeUser>::KeySize as Unsigned>::USIZE / 2)] {
                        weak |= <_ as ConstantTimeGreater>::ct_gt(v, &0);
                    }

                    if weak.unwrap_u8() == 0 {
                        Err(WeakKeyError)
                    } else {
                        Ok(())
                    }
                }
            }
        };
    }

    weak_key_test!(aes::Aes128);
    weak_key_test!(aes::Aes192);
    weak_key_test!(aes::Aes256);
}

#[cfg(feature = "des")]
mod key_test_des {
    use cipher::{typenum::Unsigned, Key, KeyInit, KeySizeUser};
    use des::{Des, TdesEde2, TdesEde3, TdesEee2, TdesEee3};
    use elliptic_curve::subtle::{Choice, ConstantTimeEq};

    use super::{TcgKeyTest, WeakKeyError};

    static WEAK_KEYS: [[u8; 8]; 64] = [
        [0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01],
        [0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE],
        [0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1],
        [0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E],
        [0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E],
        [0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01],
        [0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1],
        [0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01],
        [0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE],
        [0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01],
        [0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1],
        [0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E],
        [0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE],
        [0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E],
        [0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE],
        [0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1],
        [0x01, 0x01, 0x1F, 0x1F, 0x01, 0x01, 0x0E, 0x0E],
        [0x1F, 0x1F, 0x01, 0x01, 0x0E, 0x0E, 0x01, 0x01],
        [0xE0, 0xE0, 0x1F, 0x1F, 0xF1, 0xF1, 0x0E, 0x0E],
        [0x01, 0x01, 0xE0, 0xE0, 0x01, 0x01, 0xF1, 0xF1],
        [0x1F, 0x1F, 0xE0, 0xE0, 0x0E, 0x0E, 0xF1, 0xF1],
        [0xE0, 0xE0, 0xFE, 0xFE, 0xF1, 0xF1, 0xFE, 0xFE],
        [0x01, 0x01, 0xFE, 0xFE, 0x01, 0x01, 0xFE, 0xFE],
        [0x1F, 0x1F, 0xFE, 0xFE, 0x0E, 0x0E, 0xFE, 0xFE],
        [0xE0, 0xFE, 0x01, 0x1F, 0xF1, 0xFE, 0x01, 0x0E],
        [0x01, 0x1F, 0x1F, 0x01, 0x01, 0x0E, 0x0E, 0x01],
        [0x1F, 0xE0, 0x01, 0xFE, 0x0E, 0xF1, 0x01, 0xFE],
        [0xE0, 0xFE, 0x1F, 0x01, 0xF1, 0xFE, 0x0E, 0x01],
        [0x01, 0x1F, 0xE0, 0xFE, 0x01, 0x0E, 0xF1, 0xFE],
        [0x1F, 0xE0, 0xE0, 0x1F, 0x0E, 0xF1, 0xF1, 0x0E],
        [0xE0, 0xFE, 0xFE, 0xE0, 0xF1, 0xFE, 0xFE, 0xF1],
        [0x01, 0x1F, 0xFE, 0xE0, 0x01, 0x0E, 0xFE, 0xF1],
        [0x1F, 0xE0, 0xFE, 0x01, 0x0E, 0xF1, 0xFE, 0x01],
        [0xFE, 0x01, 0x01, 0xFE, 0xFE, 0x01, 0x01, 0xFE],
        [0x01, 0xE0, 0x1F, 0xFE, 0x01, 0xF1, 0x0E, 0xFE],
        [0x1F, 0xFE, 0x01, 0xE0, 0x0E, 0xFE, 0x01, 0xF1],
        [0xFE, 0x01, 0x1F, 0xE0, 0xFE, 0x01, 0x0E, 0xF1],
        [0xFE, 0x01, 0xE0, 0x1F, 0xFE, 0x01, 0xF1, 0x0E],
        [0x1F, 0xFE, 0xE0, 0x01, 0x0E, 0xFE, 0xF1, 0x01],
        [0xFE, 0x1F, 0x01, 0xE0, 0xFE, 0x0E, 0x01, 0xF1],
        [0x01, 0xE0, 0xE0, 0x01, 0x01, 0xF1, 0xF1, 0x01],
        [0x1F, 0xFE, 0xFE, 0x1F, 0x0E, 0xFE, 0xFE, 0x0E],
        [0xFE, 0x1F, 0xE0, 0x01, 0xFE, 0x0E, 0xF1, 0x01],
        [0x01, 0xE0, 0xFE, 0x1F, 0x01, 0xF1, 0xFE, 0x0E],
        [0xE0, 0x01, 0x01, 0xE0, 0xF1, 0x01, 0x01, 0xF1],
        [0xFE, 0x1F, 0x1F, 0xFE, 0xFE, 0x0E, 0x0E, 0xFE],
        [0x01, 0xFE, 0x1F, 0xE0, 0x01, 0xFE, 0x0E, 0xF1],
        [0xE0, 0x01, 0x1F, 0xFE, 0xF1, 0x01, 0x0E, 0xFE],
        [0xFE, 0xE0, 0x01, 0x1F, 0xFE, 0xF1, 0x01, 0x0E],
        [0x01, 0xFE, 0xE0, 0x1F, 0x01, 0xFE, 0xF1, 0x0E],
        [0xE0, 0x01, 0xFE, 0x1F, 0xF1, 0x01, 0xFE, 0x0E],
        [0xFE, 0xE0, 0x1F, 0x01, 0xFE, 0xF1, 0x0E, 0x01],
        [0x01, 0xFE, 0xFE, 0x01, 0x01, 0xFE, 0xFE, 0x01],
        [0xE0, 0x1F, 0x01, 0xFE, 0xF1, 0x0E, 0x01, 0xFE],
        [0xFE, 0xE0, 0xE0, 0xFE, 0xFE, 0xF1, 0xF1, 0xFE],
        [0x1F, 0x01, 0x01, 0x1F, 0x0E, 0x01, 0x01, 0x0E],
        [0xE0, 0x1F, 0x1F, 0xE0, 0xF1, 0x0E, 0x0E, 0xF1],
        [0xFE, 0xFE, 0x01, 0x01, 0xFE, 0xFE, 0x01, 0x01],
        [0x1F, 0x01, 0xE0, 0xFE, 0x0E, 0x01, 0xF1, 0xFE],
        [0xE0, 0x1F, 0xFE, 0x01, 0xF1, 0x0E, 0xFE, 0x01],
        [0xFE, 0xFE, 0x1F, 0x1F, 0xFE, 0xFE, 0x0E, 0x0E],
        [0x1F, 0x01, 0xFE, 0xE0, 0x0E, 0x01, 0xFE, 0xF1],
        [0xE0, 0xE0, 0x01, 0x01, 0xF1, 0xF1, 0x01, 0x01],
        [0xFE, 0xFE, 0xE0, 0xE0, 0xFE, 0xFE, 0xF1, 0xF1],
    ];

    impl TcgKeyTest for Des {
        #[inline]
        fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
            let mut weak = Choice::from(0);

            for weak_key in &WEAK_KEYS {
                weak |= key.ct_eq(weak_key.into());
            }

            if weak.unwrap_u8() == 0 {
                Ok(())
            } else {
                Err(WeakKeyError)
            }
        }
    }

    #[inline]
    fn weak_key_test<const SIZE: usize, U: KeyInit>(key: &Key<U>) -> Result<(), WeakKeyError> {
        let mut tmp = Key::<U>::default();

        for i in 0..<U as KeySizeUser>::KeySize::USIZE {
            // count number of set bits in byte, excluding the low-order bit - SWAR method
            let mut c = key[i] & 0xFE;

            c = (c & 0x55) + ((c >> 1) & 0x55);
            c = (c & 0x33) + ((c >> 2) & 0x33);
            c = (c & 0x0F) + ((c >> 4) & 0x0F);

            // if count is even, set low key bit to 1, otherwise 0
            tmp[i] = (key[i] & 0xFE) | u8::from(c & 0x01 != 0x01);
        }

        let mut des_key = Key::<Des>::default();
        for i in 0..SIZE {
            des_key.copy_from_slice(
                &tmp.as_slice()[i * <Des as KeySizeUser>::KeySize::USIZE
                    ..(i + 1) * <Des as KeySizeUser>::KeySize::USIZE],
            );
            Des::tcg_weak_key_test(&des_key)?;
        }
        Ok(())
    }

    impl TcgKeyTest for TdesEde3 {
        #[inline]
        fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
            weak_key_test::<3, Self>(key)
        }
    }

    impl TcgKeyTest for TdesEee3 {
        #[inline]
        fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
            weak_key_test::<3, Self>(key)
        }
    }

    impl TcgKeyTest for TdesEde2 {
        #[inline]
        fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
            weak_key_test::<2, Self>(key)
        }
    }

    impl TcgKeyTest for TdesEee2 {
        #[inline]
        fn tcg_weak_key_test(key: &Key<Self>) -> Result<(), WeakKeyError> {
            weak_key_test::<2, Self>(key)
        }
    }
}

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

    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
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

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit + TcgKeyTest,
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

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit + TcgKeyTest,
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

    EkCipher: KeySizeUser + BlockCipherEncrypt + KeyInit + TcgKeyTest,
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

    if EkCipher::tcg_weak_key_test(&sym_key).is_err() {
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
