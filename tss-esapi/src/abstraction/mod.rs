// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub mod ak;
pub mod cipher;
pub mod ek;
pub mod nv;
pub mod pcr;
pub mod public;
pub mod transient;

use crate::{attributes::ObjectAttributesBuilder, structures::PublicBuilder};

/// KeyCustomizaion allows to adjust how a key is going to be created
pub trait KeyCustomization {
    /// Alter the attributes used on key creation
    fn attributes(&self, attributes_builder: ObjectAttributesBuilder) -> ObjectAttributesBuilder {
        attributes_builder
    }

    /// Alter the key template used on key creation
    fn template(&self, template_builder: PublicBuilder) -> PublicBuilder {
        template_builder
    }
}

/// IntoKeyCustomization transforms a type into a type that support KeyCustomization
pub trait IntoKeyCustomization {
    type T: KeyCustomization;

    fn into_key_customization(self) -> Option<Self::T>;
}

impl<T: KeyCustomization> IntoKeyCustomization for T {
    type T = T;

    fn into_key_customization(self) -> Option<Self::T> {
        Some(self)
    }
}

#[derive(Debug, Copy, Clone)]
pub struct DefaultKey;
#[derive(Debug, Copy, Clone)]
pub struct DefaultKeyImpl;
impl KeyCustomization for DefaultKeyImpl {}

impl IntoKeyCustomization for DefaultKey {
    type T = DefaultKeyImpl;

    fn into_key_customization(self) -> Option<Self::T> {
        None
    }
}

impl IntoKeyCustomization for Option<DefaultKey> {
    type T = DefaultKeyImpl;

    fn into_key_customization(self) -> Option<Self::T> {
        None
    }
}
