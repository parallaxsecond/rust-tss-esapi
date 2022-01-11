// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    abstraction::{nv, IntoKeyCustomization, KeyCustomization},
    attributes::ObjectAttributesBuilder,
    handles::{KeyHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::{
        algorithm::{AsymmetricAlgorithm, HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth},
    },
    structures::{
        Digest, EccParameter, EccPoint, EccScheme, KeyDerivationFunctionScheme, Public,
        PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicRsaParametersBuilder,
        RsaExponent, RsaScheme, SymmetricDefinitionObject,
    },
    Context, Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
// Section 2.2.1.4 (Low Range) for Windows compatibility
const RSA_2048_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c00002;
const ECC_P256_EK_CERTIFICATE_NV_INDEX: u32 = 0x01c0000a;

/// Get the [`Public`] representing a default Endorsement Key
///
/// Source: TCG EK Credential Profile for TPM Family 2.0; Level 0 Version 2.3 Revision 2
/// Appendix B.3.3 and B.3.4
pub fn create_ek_public_from_default_template<IKC: IntoKeyCustomization>(
    alg: AsymmetricAlgorithm,
    key_customization: IKC,
) -> Result<Public> {
    let key_customization = key_customization.into_key_customization();

    let obj_attrs_builder = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_st_clear(false)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(false)
        .with_admin_with_policy(true)
        .with_no_da(false)
        .with_encrypted_duplication(false)
        .with_restricted(true)
        .with_decrypt(true)
        .with_sign_encrypt(false);

    let obj_attrs = if let Some(ref k) = key_customization {
        k.attributes(obj_attrs_builder)
    } else {
        obj_attrs_builder
    }
    .build()?;

    // TPM2_PolicySecret(TPM_RH_ENDORSEMENT)
    // With 32 null-bytes attached, because of the type of with_auth_policy
    let authpolicy: [u8; 64] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7,
        0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14,
        0x69, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let key_builder = match alg {
        AsymmetricAlgorithm::Rsa => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Rsa)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(Digest::try_from(authpolicy[0..32].to_vec())?)
            .with_rsa_parameters(
                PublicRsaParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_scheme(RsaScheme::Null)
                    .with_key_bits(RsaKeyBits::Rsa2048)
                    .with_exponent(RsaExponent::default())
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.decrypt())
                    .build()?,
            )
            .with_rsa_unique_identifier(PublicKeyRsa::new_empty_with_size(RsaKeyBits::Rsa2048)),
        AsymmetricAlgorithm::Ecc => PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(obj_attrs)
            .with_auth_policy(Digest::try_from(authpolicy[0..32].to_vec())?)
            .with_ecc_parameters(
                PublicEccParametersBuilder::new()
                    .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                    .with_ecc_scheme(EccScheme::Null)
                    .with_curve(EccCurve::NistP256)
                    .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                    .with_is_signing_key(obj_attrs.sign_encrypt())
                    .with_is_decryption_key(obj_attrs.decrypt())
                    .with_restricted(obj_attrs.decrypt())
                    .build()?,
            )
            .with_ecc_unique_identifier(EccPoint::new(
                EccParameter::try_from(vec![0u8; 32])?,
                EccParameter::try_from(vec![0u8; 32])?,
            )),
        AsymmetricAlgorithm::Null => {
            // TDOD: Figure out what to with Null.
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
    };

    let key_builder = if let Some(ref k) = key_customization {
        k.template(key_builder)
    } else {
        key_builder
    };
    key_builder.build()
}

/// Create the Endorsement Key object from the specification templates
pub fn create_ek_object<IKC: IntoKeyCustomization>(
    context: &mut Context,
    alg: AsymmetricAlgorithm,
    key_customization: IKC,
) -> Result<KeyHandle> {
    let ek_public = create_ek_public_from_default_template(alg, key_customization)?;

    Ok(context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Endorsement, ek_public, None, None, None, None)
        })?
        .key_handle)
}

/// Retrieve the Endorsement Key public certificate from the TPM
pub fn retrieve_ek_pubcert(context: &mut Context, alg: AsymmetricAlgorithm) -> Result<Vec<u8>> {
    let nv_idx = match alg {
        AsymmetricAlgorithm::Rsa => RSA_2048_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Ecc => ECC_P256_EK_CERTIFICATE_NV_INDEX,
        AsymmetricAlgorithm::Null => {
            // TDOD: Figure out what to with Null.
            return Err(Error::local_error(WrapperErrorKind::UnsupportedParam));
        }
    };

    let nv_idx = NvIndexTpmHandle::new(nv_idx).unwrap();

    let nv_auth_handle = TpmHandle::NvIndex(nv_idx);
    let nv_auth_handle = context.execute_without_session(|ctx| {
        ctx.tr_from_tpm_public(nv_auth_handle)
            .map(|v| NvAuth::NvIndex(v.into()))
    })?;

    context.execute_with_nullauth_session(|ctx| nv::read_full(ctx, nv_auth_handle, nv_idx))
}
