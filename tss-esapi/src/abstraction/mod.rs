// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

pub mod ak;
pub mod cipher;
pub mod ek;
pub mod nv;
pub mod transient;

use crate::attributes::ObjectAttributesBuilder;
use crate::utils::Tpm2BPublicBuilder;

/// KeyCustomizaion allows to adjust how a key is going to be created
pub trait KeyCustomization {
    /// Alter the attributes used on key creation
    fn attributes(&self, attributes_builder: ObjectAttributesBuilder) -> ObjectAttributesBuilder {
        attributes_builder
    }

    /// Alter the key template used on key creation
    fn template(&self, template_builder: Tpm2BPublicBuilder) -> Tpm2BPublicBuilder {
        template_builder
    }
}

/// DefaultKey provides a blanket implementation of KeyCustomization
#[derive(Copy, Clone, Debug)]
pub struct DefaultKey;
impl KeyCustomization for DefaultKey {}
