// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Secret sharing
//!
//! This provides encryption for the seed used for credential or duplication wrappers

use cipher::crypto_common::{typenum::Unsigned, Key, KeySizeUser};
use digest::{Digest, FixedOutputReset};
use elliptic_curve::{
    ecdh::{EphemeralSecret, SharedSecret},
    sec1::{Coordinates, FromEncodedPoint, ModulusSize, ToEncodedPoint},
    AffinePoint, Curve, CurveArithmetic, FieldBytesSize, Generate, PublicKey,
};
use log::error;
use rand::CryptoRng;
use zeroize::Zeroizing;

#[cfg(feature = "rsa")]
use rsa::{Oaep, RsaPublicKey};

use crate::{
    error::{Error, Result, WrapperErrorKind},
    structures::{EncryptedSecret, Public},
    utils::kdf::{self, KdfLabel},
};

/// Generates and encrypt a seed for a public key
///
/// See [A.10 Secret Sharing] for RSA
/// See [B.6 Secret Sharing] for ECC
///
/// # Parameters
///   - Type parameters
///     - `R` a [`CryptoRng`]
///     - `Use` an application-dependent value
///       See [Table 27: Protection Values], for the appropriate `seed Label`
///     - `K` is the type of [`Key`] we should provide a seed for
///   - Values
///     - `rng` the [`CryptoRng`] to derive a random seed or an ephemeral for the ECDH,
///     - `recipient_key` is the Public key we shall encrypt the seed to.
///
/// [A.10 Secret Sharing]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=284
/// [B.6 Secret Sharing]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=284
/// [Table 27: Protection Values]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=155
pub(super) fn secret_sharing<R, Use, K>(
    rng: &mut R,
    recipient_key: &Public,
) -> Result<(Zeroizing<Key<K>>, EncryptedSecret)>
where
    R: CryptoRng + ?Sized,
    Use: KdfLabel,
    K: KeySizeUser,
{
    #[allow(unused)]
    fn secret_sharing_hash<R, Use, K, NameHash>(
        rng: &mut R,
        recipient_key: &Public,
    ) -> Result<(Zeroizing<Key<K>>, EncryptedSecret)>
    where
        R: CryptoRng + ?Sized,
        Use: KdfLabel,
        K: KeySizeUser,
        NameHash: Digest + FixedOutputReset,
    {
        let _ = rng;

        match recipient_key {
            Public::KeyedHash { .. } | Public::SymCipher { .. } => {
                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
            #[cfg(feature = "rsa")]
            Public::Rsa { .. } => {
                let recipient_key = RsaPublicKey::try_from(recipient_key)?;
                secret_sharing_rsa::<R, Use, K, NameHash>(rng, &recipient_key)
            }
            Public::Ecc { parameters, .. } => {
                #[allow(unused_macros)] // macro may go unused if no curves are compiled in.
                macro_rules! impl_curve {
                    ($curve: ty) => {{
                        use crate::abstraction::public::AssociatedTpmCurve;
                        if parameters.ecc_curve() == <$curve>::TPM_CURVE {
                            let recipient_key = PublicKey::<$curve>::try_from(recipient_key)?;
                            return secret_sharing_ecc_curve::<R, Use, $curve, K, NameHash>(
                                rng,
                                &recipient_key,
                            );
                        }
                    }};
                }

                let _ = parameters;

                #[cfg(feature = "p192")]
                impl_curve!(p192::NistP192);
                #[cfg(feature = "p224")]
                impl_curve!(p224::NistP224);
                #[cfg(feature = "p256")]
                impl_curve!(p256::NistP256);
                #[cfg(feature = "p384")]
                impl_curve!(p384::NistP384);
                #[cfg(feature = "p521")]
                impl_curve!(p521::NistP521);
                // TODO  bnp256, bnp638, sm2p256

                Err(Error::local_error(WrapperErrorKind::InvalidParam))
            }
            #[cfg(not(feature = "rsa"))]
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
    let _ = rng;

    #[allow(unused_macros)] // macro may go unused if no hashes are compiled in.
    macro_rules! match_inner {
        ($hash: ty) => {
            secret_sharing_hash::<R, Use, K, $hash>(rng, recipient_key)
        };
    }

    super::match_name_hashing_algorithm!(recipient_key, match_inner)
}

/// Generates and encrypt a seed for a given ECC Public key on the curve
///
/// See [B.6 Secret Sharing]
///
/// # Parameters
///   - Type parameters
///     - `R` a [`CryptoRng`]
///     - `Use` an application-dependent value
///       See [Table 27: Protection Values], for the appropriate `seed Label`
///     - `C` is the [`Curve`] of the storage key to encrypt the seed to.
///     - `K` is the type of [`Key`] we should provide a seed for
///     - `NameHash` is the naming hash algorithm of the recipient key
///   - Values
///     - `rng` the [`CryptoRng`] to derive an ephemeral from for the ECDH
///     - `recipient_key` is the Public key we shall encrypt the seed to.
///
/// [B.6 Secret Sharing]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=284
/// [Table 27: Protection Values]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=155
pub(super) fn secret_sharing_ecc_curve<R, Use, C, K, NameHash>(
    rng: &mut R,
    recipient_key: &PublicKey<C>,
) -> Result<(Zeroizing<Key<K>>, EncryptedSecret)>
where
    R: CryptoRng + ?Sized,
    Use: KdfLabel,
    C: Curve + CurveArithmetic,

    K: KeySizeUser,
    NameHash: Digest + FixedOutputReset,

    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let local = EphemeralSecret::<C>::generate_from_rng(rng);
    let ecdh_secret: SharedSecret<C> = local.diffie_hellman(recipient_key);
    let local_public = local.public_key();
    drop(local);

    let seed = Zeroizing::new(kdf::kdfe::<Use, NameHash, C, K>(
        &ecdh_secret,
        &local_public,
        recipient_key,
    )?);
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
    let encrypted_seed = EncryptedSecret::from_bytes(&encrypted_seed)?;

    Ok((seed, encrypted_seed))
}

/// Generates and encrypt a seed for a given RSA public key
///
/// See [A.10 Secret Sharing]
///
/// # Parameters
///   - Type parameters
///     - `R` a [`CryptoRng`]
///     - `Use` an application-dependent value
///       See [Table 27: Protection Values], for the appropriate `seed Label`
///     - `K` is the type of [`Key`] we should provide a seed for
///     - `NameHash` is the naming hash algorithm of the recipient key
///   - Values
///     - `rng` the [`CryptoRng`] to derive a random seed from,
///     - `recipient_key` is the [`RsaPublicKey`] we shall encrypt the seed to.
///
/// [A.10 Secret Sharing]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=284
/// [Table 27: Protection Values]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=155
#[cfg(feature = "rsa")]
pub(super) fn secret_sharing_rsa<R, Use, K, NameHash>(
    rng: &mut R,
    recipient_key: &RsaPublicKey,
) -> Result<(Zeroizing<Key<K>>, EncryptedSecret)>
where
    R: CryptoRng + ?Sized,
    Use: KdfLabel,

    K: KeySizeUser,
    NameHash: Digest + FixedOutputReset,
{
    let random_seed = {
        let mut out = Zeroizing::new(Key::<K>::default());
        rng.fill_bytes(&mut out);
        out
    };
    let encrypted_seed = {
        let padding = Oaep::<NameHash>::new_with_label(Use::C_LABEL);
        recipient_key
            .encrypt(rng, padding, &random_seed)
            .map_err(|e| {
                error!("RSA OAEP encryption error: {e}");
                Error::local_error(WrapperErrorKind::InternalError)
            })?
    };
    let encrypted_secret = EncryptedSecret::from_bytes(&encrypted_seed)?;

    Ok((random_seed, encrypted_secret))
}
