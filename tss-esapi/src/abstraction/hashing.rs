// Copyright 2024 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::interface_types::algorithm::HashingAlgorithm;

/// Provides the value of the digest used in this crate for the digest.
pub trait AssociatedHashingAlgorithm {
    /// Value of the digest when interacting with the TPM.
    const TPM_DIGEST: HashingAlgorithm;
}

#[cfg(feature = "sha1")]
impl AssociatedHashingAlgorithm for sha1::Sha1 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha1;
}

#[cfg(feature = "sha2")]
impl AssociatedHashingAlgorithm for sha2::Sha256 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha256;
}

#[cfg(feature = "sha2")]
impl AssociatedHashingAlgorithm for sha2::Sha384 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha384;
}

#[cfg(feature = "sha2")]
impl AssociatedHashingAlgorithm for sha2::Sha512 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha512;
}

#[cfg(feature = "sm3")]
impl AssociatedHashingAlgorithm for sm3::Sm3 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sm3_256;
}

#[cfg(feature = "sha3")]
impl AssociatedHashingAlgorithm for sha3::Sha3_256 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha3_256;
}

#[cfg(feature = "sha3")]
impl AssociatedHashingAlgorithm for sha3::Sha3_384 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha3_384;
}

#[cfg(feature = "sha3")]
impl AssociatedHashingAlgorithm for sha3::Sha3_512 {
    const TPM_DIGEST: HashingAlgorithm = HashingAlgorithm::Sha3_512;
}
