// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use cipher::Array;
use digest::{consts::U20, Output};
use paste::paste;
use rand::CryptoRng;

use tss_esapi::{
    abstraction::{ek, AssociatedHashingAlgorithm, AsymmetricAlgorithmSelection},
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    handles::{AuthHandle, ObjectHandle},
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        session_handles::{AuthSession, PolicySession},
    },
    structures::{
        Digest, HmacScheme, KeyedHashScheme, Public, PublicBuilder, PublicKeyedHashParameters,
        Sensitive, SensitiveData, SymmetricDefinition, SymmetricDefinitionObject,
    },
    utils,
};

#[cfg(feature = "rsa")]
use tss_esapi::interface_types::key_bits::RsaKeyBits;

#[cfg(any(feature = "p256", feature = "p384"))]
use tss_esapi::interface_types::ecc::EccCurve;

use crate::common::create_ctx_with_session;

fn create_hmac<R, NameAlg, HashAlg>(rng: &mut R) -> (Public, Sensitive)
where
    R: CryptoRng + ?Sized,
    NameAlg: digest::Digest + AssociatedHashingAlgorithm,
    HashAlg: digest::Digest + AssociatedHashingAlgorithm,
{
    let seed = {
        let mut seed = Output::<NameAlg>::default();
        rng.fill_bytes(&mut seed);
        seed
    };
    let seed = Digest::from_bytes(&seed).unwrap();

    let key = {
        let mut key = Array::<u8, U20>::default();
        rng.fill_bytes(&mut key);
        key
    };

    let unique = {
        let mut hash = NameAlg::new();
        hash.update(seed.as_bytes());
        hash.update(key);
        hash.finalize()
    };
    let unique = Digest::from_bytes(&unique).unwrap();

    let sensitive = Sensitive::Bits {
        auth_value: Default::default(),
        seed_value: seed.clone(),
        sensitive: SensitiveData::from_bytes(&key).unwrap(),
    };

    let object_attributes = ObjectAttributesBuilder::new()
        .with_sign_encrypt(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(NameAlg::TPM_DIGEST)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Hmac {
            hmac_scheme: HmacScheme::new(HashAlg::TPM_DIGEST),
        }))
        .with_keyed_hash_unique_identifier(unique)
        .build()
        .unwrap();

    (public, sensitive)
}

fn test_create_duplicate_hmac<HmacNameAlg, HmacHashAlg>(ek_alg: AsymmetricAlgorithmSelection)
where
    HmacNameAlg: digest::Digest + AssociatedHashingAlgorithm,
    HmacHashAlg: digest::Digest + AssociatedHashingAlgorithm,
{
    let mut rng = rand::rng();
    let mut context = create_ctx_with_session();

    let ek_ecc = ek::create_ek_object(&mut context, ek_alg, None).unwrap();

    let (ek_pub, _, _) = context.read_public(ek_ecc).unwrap();

    let (sensitive_public, sensitive_private) =
        create_hmac::<_, HmacNameAlg, HmacHashAlg>(&mut rng);

    let dup = utils::create_duplicate(
        &mut rng,
        SymmetricDefinitionObject::Null,
        ek_pub.clone(),
        (&sensitive_public, &sensitive_private),
    )
    .expect("Create duplicate");

    // From that point, we don't have the private key anymore, only the TPM will
    drop(sensitive_private);

    let auth_hash_alg = match ek_alg {
        #[cfg(feature = "rsa")]
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048) => HashingAlgorithm::Sha256,
        #[cfg(feature = "rsa")]
        AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072 | RsaKeyBits::Rsa4096) => {
            HashingAlgorithm::Sha384
        }
        #[cfg(feature = "p256")]
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256) => HashingAlgorithm::Sha256,
        #[cfg(feature = "p384")]
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384) => HashingAlgorithm::Sha384,
        #[cfg(feature = "p521")]
        AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP521) => HashingAlgorithm::Sha512,
        other => unimplemented!("support for {other:?} is not implemented"),
    };
    let policy_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_256_CFB,
            auth_hash_alg,
        )
        .expect("Failed to call start_auth_session")
        .expect("Failed invalid session value");
    let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
    context
        .tr_sess_set_attributes(policy_session, session_attributes, session_attributes_mask)
        .expect("Failed to call tr_sess_set_attributes");

    let _ = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.policy_secret(
                PolicySession::try_from(policy_session)
                    .expect("Failed to convert auth session to policy session"),
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None,
            )
        })
        .unwrap();

    let new_parent_handle: ObjectHandle = ek_ecc.into();

    // Try to import the duplicated object.
    let _hmac_key = context
        .execute_with_session(Some(policy_session), |ctx| {
            ctx.import(
                new_parent_handle,
                None,
                sensitive_public,
                dup.payload,
                dup.seed_ciphertext,
                SymmetricDefinitionObject::Null,
            )
        })
        .unwrap();

    //let loaded_storage_key_2 = context
    //    .execute_with_nullauth_session(|ctx| {
    //        ctx.load(hmac_key_handle.into(), private_storage_key_2, public)
    //    })
    //    .unwrap();
}

macro_rules! test_import {
    ($hmac_name: ty, $hmac_hash: ty) => {
        paste! {
            #[cfg(feature = "rsa")]
            #[test]
            fn [<test_create_duplicate_hmac_rsa2048_ $hmac_name:lower _ $hmac_hash:lower>]() {
                test_create_duplicate_hmac::<$hmac_name, $hmac_hash>(
                    AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048)
                )
            }

            #[cfg(feature = "rsa")]
            #[test]
            fn [<test_create_duplicate_hmac_rsa3072_ $hmac_name:lower _ $hmac_hash:lower>]() {
                test_create_duplicate_hmac::<$hmac_name, $hmac_hash>(
                    AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa3072)
                )
            }

            #[cfg(feature = "p256")]
            #[test]
            fn [<test_create_duplicate_hmac_p256_ $hmac_name:lower _ $hmac_hash:lower>]() {
                test_create_duplicate_hmac::<$hmac_name, $hmac_hash>(
                    AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
                )
            }

            #[cfg(feature = "p384")]
            #[test]
            fn [<test_create_duplicate_hmac_p384_ $hmac_name:lower _ $hmac_hash:lower>]() {
                test_create_duplicate_hmac::<$hmac_name, $hmac_hash>(
                    AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP384),
                )
            }
        }
    };
    (hmac_name=$hmac_name:ty, hmac_hashes=($hmac_hash:ty)) => {
        test_import!($hmac_name, $hmac_hash);
    };
    (hmac_name=$hmac_name:ty, hmac_hashes=($hmac_hash:ty, $($hmac_hashes:ty),+)) => {
        test_import!($hmac_name, $hmac_hash);
        test_import!(hmac_name=$hmac_name, hmac_hashes=($($hmac_hashes),+));
    };
    (hmac_names=($hmac_name:ty), hmac_hashes=($($hmac_hashes:ty),+)) => {
        test_import!(hmac_name=$hmac_name, hmac_hashes=($($hmac_hashes),+));
    };
    (hmac_names=($hmac_name:ty, $($hmac_names:ty),+), hmac_hashes=($($hmac_hashes:ty),+)) => {
        test_import!(hmac_name=$hmac_name, hmac_hashes=($($hmac_hashes),+));
        test_import!(hmac_names=($($hmac_names),+), hmac_hashes=($($hmac_hashes),+));
    };
}

#[cfg(feature = "sha1")]
use sha1::Sha1;
#[cfg(feature = "sha1")]
test_import!(hmac_names = (Sha1), hmac_hashes = (Sha1));

#[cfg(feature = "sha2")]
use sha2::{Sha256, Sha384, Sha512};

#[cfg(feature = "sha2")]
test_import!(
    hmac_names = (Sha256, Sha384, Sha512),
    hmac_hashes = (Sha256, Sha384, Sha512)
);

/* No support for sha3 or sm3 in libtpms
#[cfg(feature = "sha3")]
use sha3::{Sha3_256, Sha3_384, Sha3_512};
#[cfg(feature = "sha3")]
test_import!(
    hmac_names = (Sha3_256, Sha3_384, Sha3_512),
    hmac_hashes = (Sha3_256, Sha3_384, Sha3_512)
);

#[cfg(feature = "sm3")]
use sm3::Sm3;
#[cfg(feature = "sm3")]
test_import!(Sm3, Sm3)
*/
