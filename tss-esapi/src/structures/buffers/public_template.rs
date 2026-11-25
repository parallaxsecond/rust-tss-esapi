// Copyright 2026 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    Error, Result, WrapperErrorKind,
    structures::Public,
    traits::{Marshall, UnMarshall, impl_mu_standard},
    tss2_esys::{TPM2B_TEMPLATE, UINT16},
};
use log::error;
use std::{convert::TryFrom, mem::size_of, ops::Deref};
use zeroize::{Zeroize, Zeroizing};

/// A public template used when creating and loading an object in one operation.
///
/// This type corresponds to `TPM2B_TEMPLATE`. It stores either a marshalled [Public] structure or
/// a raw derivation template. Use the byte conversions when constructing a derivation template.
///
/// # Example
///
/// ```rust
/// use std::convert::TryFrom;
/// use tss_esapi::{
///     interface_types::{
///         algorithm::{HashingAlgorithm, RsaSchemeAlgorithm},
///         key_bits::RsaKeyBits,
///     },
///     structures::{Public, PublicTemplate, RsaExponent, RsaScheme},
///     utils::create_unrestricted_signing_rsa_public,
/// };
///
/// let public = create_unrestricted_signing_rsa_public(
///     RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
///         .expect("Failed to create RSA scheme"),
///     RsaKeyBits::Rsa2048,
///     RsaExponent::default(),
/// )
/// .expect("Failed to create public area");
/// let template = PublicTemplate::try_from(public.clone())
///     .expect("Failed to create public template");
///
/// assert_eq!(
///     public,
///     Public::try_from(template).expect("Failed to decode public template")
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct PublicTemplate(Zeroizing<Vec<u8>>);

impl Default for PublicTemplate {
    fn default() -> Self {
        Self(Vec::new().into())
    }
}

impl PublicTemplate {
    /// Maximum size of a public template in bytes.
    pub const MAX_SIZE: usize = size_of::<TPM2B_TEMPLATE>() - size_of::<UINT16>();

    /// Creates a public template containing the supplied bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "bytes(&[u8])")?;
        Ok(Self(bytes.to_vec().into()))
    }

    /// Returns the raw template bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn ensure_valid_buffer_size(buffer_size: usize, container_name: &str) -> Result<()> {
        if buffer_size > Self::MAX_SIZE {
            error!(
                "Invalid {} size for PublicTemplate (> {})",
                container_name,
                Self::MAX_SIZE
            );
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        Ok(())
    }
}

impl AsRef<[u8]> for PublicTemplate {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl Deref for PublicTemplate {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TryFrom<Vec<u8>> for PublicTemplate {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::ensure_valid_buffer_size(bytes.len(), "Vec<u8>")?;
        Ok(Self(bytes.into()))
    }
}

impl TryFrom<&[u8]> for PublicTemplate {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl TryFrom<TPM2B_TEMPLATE> for PublicTemplate {
    type Error = Error;

    fn try_from(template: TPM2B_TEMPLATE) -> Result<Self> {
        let size = template.size as usize;
        Self::ensure_valid_buffer_size(size, "TPM2B_TEMPLATE buffer")?;
        Ok(Self(template.buffer[..size].to_vec().into()))
    }
}

impl From<PublicTemplate> for TPM2B_TEMPLATE {
    fn from(template: PublicTemplate) -> Self {
        let mut ffi_template = TPM2B_TEMPLATE {
            size: template.0.len() as u16,
            ..Default::default()
        };
        ffi_template.buffer[..template.0.len()].copy_from_slice(&template.0);
        ffi_template
    }
}

impl TryFrom<Public> for PublicTemplate {
    type Error = Error;

    fn try_from(public: Public) -> Result<Self> {
        Self::try_from(public.marshall()?)
    }
}

impl TryFrom<PublicTemplate> for Public {
    type Error = Error;

    fn try_from(template: PublicTemplate) -> Result<Self> {
        Self::unmarshall(template.as_bytes())
    }
}

impl_mu_standard!(PublicTemplate, TPM2B_TEMPLATE);
