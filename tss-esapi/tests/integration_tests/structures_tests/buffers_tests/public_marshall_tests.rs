// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use tss_esapi::attributes::ObjectAttributes;
use tss_esapi::interface_types::algorithm::*;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::structures::*;
use tss_esapi::traits::{Marshall, UnMarshall};

use crate::common::setup_logging;

#[test]
fn test_marshall_unmarshall() {
    setup_logging();

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_object_attributes(ObjectAttributes::new_fixed_parent_key())
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_restricted(false)
                .with_is_decryption_key(false)
                .with_is_signing_key(true)
                .with_ecc_scheme(
                    EccScheme::create(
                        EccSchemeAlgorithm::EcDsa,
                        Some(HashingAlgorithm::Sha256),
                        None,
                    )
                    .unwrap(),
                )
                .with_curve(EccCurve::NistP256)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .with_symmetric(SymmetricDefinitionObject::Null)
                .build()
                .expect("Failed to build public ECC parameters"),
        )
        .with_ecc_unique_identifier(&EccPoint::default())
        .build()
        .expect("Failed to build public data");

    let pub_data_vec = public.marshall().expect("Failed to marshall public data");

    let new_public = Public::unmarshall(&pub_data_vec).expect("Failed to unmarshall public data");

    assert_eq!(new_public, public);
}
