// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
#![cfg_attr(
    not(any(feature = "sha1", feature = "sha2", feature = "sha3", feature = "sm3",)),
    allow(unused)
)]

//! This module holds the logic to implement Duplication as
//! defined in the [Section 21.3 Duplication] of the specification.
//!
//! [Section 21.3 Duplication]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=162

use core::ops::Mul;

use cfb_mode::Encryptor;
use cipher::{
    array::ArraySize, consts::U8, typenum::Unsigned, AsyncStreamCipher, BlockCipherEncrypt, Iv,
    Key, KeyInit, KeyIvInit, KeySizeUser,
};
use digest::{crypto_common::OutputSize, Digest, FixedOutputReset, OutputSizeUser};
use hmac::{EagerHash, Hmac, Mac};
use log::error;
use rand::CryptoRng;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    abstraction::AssociatedHashingAlgorithm,
    error::{Error, Result, WrapperErrorKind},
    interface_types::{
        algorithm::SymmetricMode,
        key_bits::{AesKeyBits, CamelliaKeyBits, Sm4KeyBits},
    },
    structures::{EncryptedSecret, Name, Private, Public, Sensitive, SymmetricDefinitionObject},
    traits::Marshall,
    utils::{
        hash_object,
        kdf::{self, kdfa},
        secret_sharing, TpmHmac,
    },
};

struct InnerWrapper {
    sym_key: Option<Zeroizing<Box<[u8]>>>,
    enc_sensitive: Zeroizing<Box<[u8]>>,
}

/// In the first phase, we'll compute the integrity hash of the sensitive data. The hash includes
/// the Name of the public area associated with this object.
///
/// # Parameters
///
///  - Type parameters:
///    - `H` is the [`Digest`] nameAlg of the object.
///  - Parameters
///    - `sensitive`
///
///
/// See [Section 21.3.2.2 Inner Duplication Wrapper] for details.
///
/// [Section 21.3.2.2 Inner Duplication Wrapper]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=162
fn inner_wrapper<R, PSymAlg>(
    rng: &mut R,
    sensitive_kp: (&Public, &Sensitive),
) -> Result<InnerWrapper>
where
    R: CryptoRng + ?Sized,
    PSymAlg: BlockCipherEncrypt + KeyInit,
{
    fn inner_wrapper_hash<R, PSymAlg, NameAlg>(
        rng: &mut R,
        sensitive_kp: (&Public, &Sensitive),
    ) -> Result<InnerWrapper>
    where
        R: CryptoRng + ?Sized,
        PSymAlg: BlockCipherEncrypt + KeyInit,
        NameAlg: Digest,
    {
        let (sensitive_pub, sensitive_priv) = sensitive_kp;

        let sym_key = Zeroizing::new(loop {
            let mut key = Key::<PSymAlg>::default();
            rng.fill_bytes(&mut key);

            if PSymAlg::weak_key_test(&key).is_ok() {
                break key;
            }
        });

        // Name of the object being protected
        let name = sensitive_pub.name()?;

        // innerIntegrity ∶= H_nameAlg(sensitive ∥ name)
        let inner_integrity = {
            let mut d = NameAlg::new();
            hash_object(&mut d, sensitive_priv)?;
            d.update(name.value());

            d.finalize()
        };

        // encSensitive ∶= CFB_pSymAlg(symKey, 0, innerIntegrity ∥ sensitive)
        let mut enc_sensitive: Zeroizing<Box<[u8]>> = Zeroizing::new({
            let mut out = Vec::with_capacity(inner_integrity.len() + 2 + Sensitive::BUFFER_SIZE);
            out.extend_from_slice(&inner_integrity);
            out.append(&mut sensitive_priv.marshall_prefixed()?);
            out.to_vec().into()
        });
        let iv = {
            let mut iv = Iv::<Encryptor<PSymAlg>>::default();
            iv.zeroize();
            iv
        };
        let enc = Encryptor::<PSymAlg>::new(&sym_key, &iv);
        enc.encrypt(enc_sensitive.as_mut().as_mut());

        Ok(InnerWrapper {
            enc_sensitive,
            sym_key: Some(Zeroizing::new({
                let key: &[u8] = sym_key.as_ref();
                key.to_vec().into()
            })),
        })
    }

    let (sensitive_pub, _sensitive_priv) = sensitive_kp;

    // TODO: is this really? There are subtilities of the key is FIXED_TPM
    //if !sensitive_pub.object_attributes().encrypted_duplication() {
    //    if new_parent.is_none() {
    //        todo!("error, the new parent can't be null");
    //    }

    //    // encSensitive := sensitive
    //    todo!("no inner wrapper, encsensitive is directly sensitive");
    //}

    macro_rules! match_inner {
        ($hash: ty) => {
            inner_wrapper_hash::<R, PSymAlg, $hash>(rng, sensitive_kp)
        };
    }

    super::match_name_hashing_algorithm!(sensitive_pub, match_inner)
}

/// See [Section 21.3.2.3 Outer Duplication Wrapper] for details.
///
/// [Section 21.3.2.3 Outer Duplication Wrapper]: https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=163
fn outer_wrapper<R, NpNameAlg, NpSymAlg>(
    rng: &mut R,
    new_parent: &Public,
    enc_sensitive: &mut Zeroizing<Box<[u8]>>,
    sensitive_public: &Public,
) -> Result<(EncryptedSecret, Private)>
where
    R: CryptoRng + ?Sized,

    // NOTE: NP stands for New Parent
    NpNameAlg: Digest + FixedOutputReset + EagerHash,
    NpSymAlg: BlockCipherEncrypt + KeyInit,
    NpNameAlg: OutputSizeUser,
    NpNameAlg: AssociatedHashingAlgorithm,

    // Use of kdfa
    // vvvvvvvvvvv
    NpNameAlg::OutputSize: ArraySize + Mul<U8>,
    <NpNameAlg::OutputSize as Mul<U8>>::Output: Unsigned,

    NpSymAlg: KeySizeUser,

    NpSymAlg::KeySize: ArraySize + Mul<U8>,
    <NpSymAlg::KeySize as Mul<U8>>::Output: Unsigned,

    <<NpNameAlg as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
    <<<NpNameAlg as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output: Unsigned,
{
    fn outer_wrapper_obj<R, ObjNameAlg, NpNameAlg, NpSymAlg>(
        rng: &mut R,
        new_parent: &Public,
        enc_sensitive: &mut Zeroizing<Box<[u8]>>,
        sensitive_name: Name,
    ) -> Result<(EncryptedSecret, Private)>
    where
        R: CryptoRng + ?Sized,

        // ObjNameAlg is the Name Algorithm of the object being duplicated
        ObjNameAlg: AssociatedHashingAlgorithm,

        // NOTE: NP stands for New Parent
        NpNameAlg: Digest + FixedOutputReset + EagerHash,
        NpSymAlg: BlockCipherEncrypt + KeyInit,
        NpNameAlg: OutputSizeUser,
        NpNameAlg: AssociatedHashingAlgorithm,

        // Use of kdfa
        // vvvvvvvvvvv
        NpNameAlg::OutputSize: ArraySize + Mul<U8>,
        <NpNameAlg::OutputSize as Mul<U8>>::Output: Unsigned,

        NpSymAlg: KeySizeUser,

        NpSymAlg::KeySize: ArraySize + Mul<U8>,
        <NpSymAlg::KeySize as Mul<U8>>::Output: Unsigned,

        <<NpNameAlg as EagerHash>::Core as OutputSizeUser>::OutputSize: ArraySize + Mul<U8>,
        <<<NpNameAlg as EagerHash>::Core as OutputSizeUser>::OutputSize as Mul<U8>>::Output:
            Unsigned,
    {
        // Create a seed and encrypt it for the new parent
        let (seed, seed_ciphertext) = encapsulate::<R, TpmHmac<NpNameAlg>>(rng, new_parent)?;

        // symKey ∶= KDFa(npNameAlg, seed, "STORAGE", Name, NULL, bits)
        let mut name = vec![];
        let hash_prefix = &u16::from(ObjNameAlg::TPM_DIGEST).to_be_bytes()[..];
        name.extend_from_slice(hash_prefix);
        name.extend_from_slice(sensitive_name.value());
        let sym_key = kdfa::<NpNameAlg, kdf::Storage, NpSymAlg>(&seed, &name, &[])?;

        // dupSensitive ∶= CFB_npSymAlg(symKey, 0, encSensitive)
        let iv = {
            let mut iv = Iv::<Encryptor<NpSymAlg>>::default();
            iv.zeroize();
            iv
        };
        let enc = Encryptor::<NpSymAlg>::new(&sym_key, &iv);
        enc.encrypt(enc_sensitive.as_mut().as_mut());

        // HMACkey ∶= KDFa(npNameAlg, seed, "INTEGRITY", NULL, NULL, bits)
        let hmac_key = kdfa::<NpNameAlg, kdf::Integrity, TpmHmac<NpNameAlg>>(&seed, &[], &[])?;

        // outerHMAC ∶= HMAC_npNameAlg(HMACkey, dupSensitive ∥ Name)
        let mut outer_hmac = Hmac::<NpNameAlg>::new_from_slice(&hmac_key).map_err(|e| {
            error!("Outer HMAC key derivation error: {e}");
            Error::local_error(WrapperErrorKind::InternalError)
        })?;
        outer_hmac.update(enc_sensitive.as_ref());
        let hash_prefix = &u16::from(ObjNameAlg::TPM_DIGEST).to_be_bytes()[..];
        outer_hmac.update(hash_prefix);
        outer_hmac.update(sensitive_name.value());
        let outer_hmac = outer_hmac.finalize();

        let mut out = Vec::with_capacity(
            (u16::BITS / 8) as usize + OutputSize::<Hmac<NpNameAlg>>::USIZE + enc_sensitive.len(),
        );
        out.append(&mut outer_hmac.marshall_prefixed()?);
        out.extend_from_slice(enc_sensitive);
        Private::from_bytes(&out).map(|p| (seed_ciphertext, p))
    }

    macro_rules! match_inner {
        ($hash: ty) => {
            outer_wrapper_obj::<R, $hash, NpNameAlg, NpSymAlg>(
                rng,
                new_parent,
                enc_sensitive,
                sensitive_public.name()?,
            )
        };
    }

    super::match_name_hashing_algorithm!(sensitive_public, match_inner)
}

/// Payload for a duplicate object
#[derive(Debug)]
pub struct DuplicatePayload {
    /// Symmetric encryption key
    pub sym_key: Option<Zeroizing<Box<[u8]>>>,
    /// Duplicate payload
    pub payload: Private,
    /// Seed ciphertext
    /// This is the seed used to encrypt the outer wrapper of the object
    pub seed_ciphertext: EncryptedSecret,
}

/// [`create_duplicate`] allows to encrypt an object and import it under a Storage Key.
///
/// This is a mashup of Create and Duplicate commands. The Duplicate command will accept an
/// external key instead of using an object held on TPM.
///
/// This is used in draft specs like [EK-Based key attestation with TPM firmware version].
///
/// [EK-Based key attestation with TPM firmware version]: https://trustedcomputinggroup.org/wp-content/uploads/EK-Based-Key-Attestation-with-TPM-Firmware-Version-V1-RC1_9July2025.pdf
// Note: an implementation can be found used in the reference implementation of the draft.
// See <https://github.com/chrisfenner/go-tpm/blob/d4e7ae80143dac006977714eaee27ef2c67c106f/tpm2/create_duplicate.go>
pub fn create_duplicate<R>(
    rng: &mut R,
    symmetric_alg: SymmetricDefinitionObject,
    new_parent: Public,
    sensitive_kp: (&Public, &Sensitive),
) -> Result<DuplicatePayload>
where
    R: CryptoRng + ?Sized,
{
    fn create_duplicate_inner<R, NpSymAlg>(
        rng: &mut R,
        symmetric_alg: SymmetricDefinitionObject,
        new_parent: &Public,
        sensitive_kp: (&Public, &Sensitive),
    ) -> Result<DuplicatePayload>
    where
        R: CryptoRng + ?Sized,
        NpSymAlg: BlockCipherEncrypt + KeyInit,

        // Use of kdfa
        // vvvvvvvvvvv
        NpSymAlg: KeySizeUser,

        NpSymAlg::KeySize: ArraySize + Mul<U8>,
        <NpSymAlg::KeySize as Mul<U8>>::Output: Unsigned,
    {
        // TODO: probably should check sensitive_kp public is not fixed tpm?

        let InnerWrapper {
            sym_key,
            mut enc_sensitive,
        } = match symmetric_alg {
            SymmetricDefinitionObject::Null => {
                // If symmetric_algorithm is null, then no inner wrapper is required, just return the
                // sensitive directly (prepended with its size).
                let enc_sensitive: Zeroizing<Box<[u8]>> =
                    Zeroizing::new(sensitive_kp.1.marshall_prefixed()?.into());

                Ok(InnerWrapper {
                    sym_key: None,
                    enc_sensitive,
                })
            }

            // Only CFB mode is supported
            SymmetricDefinitionObject::Aes {
                mode:
                    SymmetricMode::Ctr
                    | SymmetricMode::Ofb
                    | SymmetricMode::Cbc
                    | SymmetricMode::Ecb
                    | SymmetricMode::Null,
                ..
            }
            | SymmetricDefinitionObject::Sm4 {
                mode:
                    SymmetricMode::Ctr
                    | SymmetricMode::Ofb
                    | SymmetricMode::Cbc
                    | SymmetricMode::Ecb
                    | SymmetricMode::Null,
                ..
            }
            | SymmetricDefinitionObject::Camellia {
                mode:
                    SymmetricMode::Ctr
                    | SymmetricMode::Ofb
                    | SymmetricMode::Cbc
                    | SymmetricMode::Ecb
                    | SymmetricMode::Null,
                ..
            } => Err(Error::local_error(WrapperErrorKind::InvalidParam)),

            #[cfg(feature = "aes")]
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes128,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, aes::Aes128>(rng, sensitive_kp),
            #[cfg(feature = "aes")]
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes192,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, aes::Aes192>(rng, sensitive_kp),
            #[cfg(feature = "aes")]
            SymmetricDefinitionObject::Aes {
                key_bits: AesKeyBits::Aes256,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, aes::Aes256>(rng, sensitive_kp),
            #[cfg(feature = "sm4")]
            SymmetricDefinitionObject::Sm4 {
                key_bits: Sm4KeyBits::Sm4_128,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, sm4::Sm4>(rng, sensitive_kp),
            #[cfg(feature = "camellia")]
            SymmetricDefinitionObject::Camellia {
                key_bits: CamelliaKeyBits::Camellia128,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, camellia::Camellia128>(rng, sensitive_kp),
            #[cfg(feature = "camellia")]
            SymmetricDefinitionObject::Camellia {
                key_bits: CamelliaKeyBits::Camellia192,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, camellia::Camellia192>(rng, sensitive_kp),
            #[cfg(feature = "camellia")]
            SymmetricDefinitionObject::Camellia {
                key_bits: CamelliaKeyBits::Camellia256,
                mode: SymmetricMode::Cfb,
            } => inner_wrapper::<R, camellia::Camellia256>(rng, sensitive_kp),

            #[cfg(not(all(feature = "aes", feature = "sm4", feature = "camellia")))]
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }?;

        macro_rules! match_inner {
            ($hash: ty) => {
                outer_wrapper::<R, $hash, NpSymAlg>(
                    rng,
                    new_parent,
                    &mut enc_sensitive,
                    sensitive_kp.0,
                )
            };
        }

        let (seed_ciphertext, payload) =
            super::match_name_hashing_algorithm!(new_parent, match_inner)?;

        Ok(DuplicatePayload {
            sym_key,
            payload,
            seed_ciphertext,
        })
    }

    match new_parent.symmetric_algorithm()? {
        SymmetricDefinitionObject::Null => Err(Error::local_error(WrapperErrorKind::InvalidParam)),

        // Only CFB mode is supported
        SymmetricDefinitionObject::Aes {
            mode:
                SymmetricMode::Ctr
                | SymmetricMode::Ofb
                | SymmetricMode::Cbc
                | SymmetricMode::Ecb
                | SymmetricMode::Null,
            ..
        }
        | SymmetricDefinitionObject::Sm4 {
            mode:
                SymmetricMode::Ctr
                | SymmetricMode::Ofb
                | SymmetricMode::Cbc
                | SymmetricMode::Ecb
                | SymmetricMode::Null,
            ..
        }
        | SymmetricDefinitionObject::Camellia {
            mode:
                SymmetricMode::Ctr
                | SymmetricMode::Ofb
                | SymmetricMode::Cbc
                | SymmetricMode::Ecb
                | SymmetricMode::Null,
            ..
        } => Err(Error::local_error(WrapperErrorKind::InvalidParam)),

        #[cfg(feature = "aes")]
        SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes128,
            mode: SymmetricMode::Cfb,
        } => {
            create_duplicate_inner::<R, aes::Aes128>(rng, symmetric_alg, &new_parent, sensitive_kp)
        }
        #[cfg(feature = "aes")]
        SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes192,
            mode: SymmetricMode::Cfb,
        } => {
            create_duplicate_inner::<R, aes::Aes192>(rng, symmetric_alg, &new_parent, sensitive_kp)
        }
        #[cfg(feature = "aes")]
        SymmetricDefinitionObject::Aes {
            key_bits: AesKeyBits::Aes256,
            mode: SymmetricMode::Cfb,
        } => {
            create_duplicate_inner::<R, aes::Aes256>(rng, symmetric_alg, &new_parent, sensitive_kp)
        }
        #[cfg(feature = "sm4")]
        SymmetricDefinitionObject::Sm4 {
            key_bits: Sm4KeyBits::Sm4_128,
            mode: SymmetricMode::Cfb,
        } => create_duplicate_inner::<R, sm4::Sm4>(rng, symmetric_alg, &new_parent, sensitive_kp),
        #[cfg(feature = "camellia")]
        SymmetricDefinitionObject::Camellia {
            key_bits: CamelliaKeyBits::Camellia128,
            mode: SymmetricMode::Cfb,
        } => create_duplicate_inner::<R, camellia::Camellia128>(
            rng,
            symmetric_alg,
            &new_parent,
            sensitive_kp,
        ),
        #[cfg(feature = "camellia")]
        SymmetricDefinitionObject::Camellia {
            key_bits: CamelliaKeyBits::Camellia192,
            mode: SymmetricMode::Cfb,
        } => create_duplicate_inner::<R, camellia::Camellia192>(
            rng,
            symmetric_alg,
            &new_parent,
            sensitive_kp,
        ),
        #[cfg(feature = "camellia")]
        SymmetricDefinitionObject::Camellia {
            key_bits: CamelliaKeyBits::Camellia256,
            mode: SymmetricMode::Cfb,
        } => create_duplicate_inner::<R, camellia::Camellia256>(
            rng,
            symmetric_alg,
            &new_parent,
            sensitive_kp,
        ),

        #[cfg(not(all(feature = "aes", feature = "sm4", feature = "camellia")))]
        _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
    }
}

fn encapsulate<R, K>(
    rng: &mut R,
    storage_key: &Public,
) -> Result<(Zeroizing<Key<K>>, EncryptedSecret)>
where
    R: CryptoRng + ?Sized,
    K: KeySizeUser,
{
    if !storage_key.object_attributes().decrypt() {
        return Err(Error::local_error(WrapperErrorKind::InvalidParam));
    }

    secret_sharing::secret_sharing::<R, kdf::Duplicate, K>(rng, storage_key)
}

// NOTES:
//
// Secret sharing
// https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf#page=284
// A.10 Secret Sharing
