// Copyright 2019 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
//! Utility module
//!
//! This module mostly contains helper elements meant to act as either wrappers around FFI-level
//! structs or builders for them, along with other convenience elements.
//! The naming structure usually takes the names inherited from the TSS spec and applies Rust
//! guidelines to them. Structures that are meant to act as builders have `Builder` appended to
//! type name. Unions are converted to Rust `enum`s by dropping the `TPMU` qualifier and appending
//! `Union`.
use crate::attributes::{ObjectAttributes, ObjectAttributesBuilder};
use crate::constants::tss::*;
use crate::constants::PropertyTag;
use crate::interface_types::{algorithm::HashingAlgorithm, ecc::EllipticCurve};
use crate::structures::{Digest, KeyedHashParms, PcrSlot};
use crate::tss2_esys::*;
use crate::{Context, Error, Result, WrapperErrorKind};
use enumflags2::BitFlags;
use log::error;
use zeroize::Zeroize;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::{TryFrom, TryInto};
/// Helper for building `TPM2B_PUBLIC` values out of its subcomponents.
///
/// Currently the implementation is incomplete, focusing on creating objects of RSA type.
// Most of the field types are from bindgen which does not implement Debug on them.
#[allow(missing_debug_implementations)]
pub struct Tpm2BPublicBuilder {
    type_: Option<TPMI_ALG_PUBLIC>,
    name_alg: TPMI_ALG_HASH,
    object_attributes: ObjectAttributes,
    auth_policy: TPM2B_DIGEST,
    parameters: Option<PublicParmsUnion>,
    unique: Option<PublicIdUnion>,
}

impl Tpm2BPublicBuilder {
    /// Create a new builder with default (i.e. empty or null) placeholder values.
    pub fn new() -> Self {
        Tpm2BPublicBuilder {
            type_: None,
            name_alg: TPM2_ALG_NULL,
            object_attributes: ObjectAttributes(0),
            auth_policy: Default::default(),
            parameters: None,
            unique: None,
        }
    }

    /// Set the type of the object to be built.
    pub fn with_type(mut self, type_: TPMI_ALG_PUBLIC) -> Self {
        self.type_ = Some(type_);
        self
    }

    /// Set the algorithm used to derive the object name.
    pub fn with_name_alg(mut self, name_alg: TPMI_ALG_HASH) -> Self {
        self.name_alg = name_alg;
        self
    }

    /// Set the object attributes.
    pub fn with_object_attributes(mut self, obj_attr: ObjectAttributes) -> Self {
        self.object_attributes = obj_attr;
        self
    }

    /// Set the authentication policy hash for the object.
    pub fn with_auth_policy(mut self, size: u16, buffer: [u8; 64]) -> Self {
        self.auth_policy = TPM2B_DIGEST { size, buffer };
        self
    }

    /// Set the public parameters of the object.
    pub fn with_parms(mut self, parameters: PublicParmsUnion) -> Self {
        self.parameters = Some(parameters);
        self
    }

    /// Set the unique value for the object.
    pub fn with_unique(mut self, unique: PublicIdUnion) -> Self {
        self.unique = Some(unique);
        self
    }

    /// Build an object with the previously provided parameters.
    ///
    /// The paramters are checked for consistency based on the TSS specifications for the
    /// `TPM2B_PUBLIC` structure and for the structures nested within it.
    ///
    /// Currently only objects of type `TPM2_ALG_RSA` are supported.
    ///
    /// # Errors
    /// * if no public parameters are provided, `ParamsMissing` wrapper error is returned
    /// * if a public parameter type or public ID type is provided that is incosistent with the
    /// object type provided, `InconsistentParams` wrapper error is returned
    ///
    /// # Panics
    /// * will panic on unsupported platforms (i.e. on 8 bit processors)
    pub fn build(self) -> Result<TPM2B_PUBLIC> {
        match self.type_ {
            Some(TPM2_ALG_RSA) => {
                // RSA key
                let parameters;
                let unique;
                if let Some(PublicParmsUnion::RsaDetail(parms)) = self.parameters {
                    parameters = TPMU_PUBLIC_PARMS { rsaDetail: parms };
                } else if self.parameters.is_none() {
                    return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                if let Some(PublicIdUnion::Rsa(rsa_unique)) = self.unique {
                    unique = TPMU_PUBLIC_ID { rsa: *rsa_unique };
                } else if self.unique.is_none() {
                    unique = Default::default();
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                Ok(TPM2B_PUBLIC {
                    size: std::mem::size_of::<TPMT_PUBLIC>()
                        .try_into()
                        .expect("Failed to convert usize to u16"), // should not fail on valid targets
                    publicArea: TPMT_PUBLIC {
                        type_: self.type_.unwrap(), // cannot fail given that this is inside a match on `type_`
                        nameAlg: self.name_alg,
                        objectAttributes: self.object_attributes.0,
                        authPolicy: self.auth_policy,
                        parameters,
                        unique,
                    },
                })
            }
            Some(TPM2_ALG_ECC) => {
                // ECC key
                let parameters;
                let unique;
                if let Some(PublicParmsUnion::EccDetail(parms)) = self.parameters {
                    parameters = TPMU_PUBLIC_PARMS { eccDetail: parms };
                } else if self.parameters.is_none() {
                    return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                if let Some(PublicIdUnion::Ecc(rsa_unique)) = self.unique {
                    unique = TPMU_PUBLIC_ID { ecc: *rsa_unique };
                } else if self.unique.is_none() {
                    unique = Default::default();
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                Ok(TPM2B_PUBLIC {
                    size: std::mem::size_of::<TPMT_PUBLIC>()
                        .try_into()
                        .expect("Failed to convert usize to u16"), // should not fail on valid targets
                    publicArea: TPMT_PUBLIC {
                        type_: self.type_.unwrap(), // cannot fail given that this is inside a match on `type_`
                        nameAlg: self.name_alg,
                        objectAttributes: self.object_attributes.0,
                        authPolicy: self.auth_policy,
                        parameters,
                        unique,
                    },
                })
            }
            Some(TPM2_ALG_KEYEDHASH) => {
                // KeyedHash
                let parameters;
                let unique;
                if let Some(PublicParmsUnion::KeyedHashDetail(parms)) = self.parameters {
                    parameters = TPMU_PUBLIC_PARMS {
                        keyedHashDetail: parms.into(),
                    };
                } else if self.parameters.is_none() {
                    return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                if let Some(PublicIdUnion::KeyedHash(hash_unique)) = self.unique {
                    unique = TPMU_PUBLIC_ID {
                        keyedHash: hash_unique,
                    };
                } else if self.unique.is_none() {
                    unique = Default::default();
                } else {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }

                Ok(TPM2B_PUBLIC {
                    size: std::mem::size_of::<TPMT_PUBLIC>()
                        .try_into()
                        .expect("Failed to convert usize to u16"), // should not fail on valid targets
                    publicArea: TPMT_PUBLIC {
                        type_: self.type_.unwrap(), // cannot fail given that this is inside a match on `type_`
                        nameAlg: self.name_alg,
                        objectAttributes: self.object_attributes.0,
                        authPolicy: self.auth_policy,
                        parameters,
                        unique,
                    },
                })
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

impl Default for Tpm2BPublicBuilder {
    fn default() -> Self {
        Tpm2BPublicBuilder::new()
    }
}

/// Builder for `TPMS_RSA_PARMS` values.
// Most of the field types are from bindgen which does not implement Debug on them.
#[allow(missing_debug_implementations)]
#[derive(Copy, Clone, Default)]
pub struct TpmsRsaParmsBuilder {
    /// Symmetric cipher to be used in conjuction with the key
    pub symmetric: Option<TPMT_SYM_DEF_OBJECT>,
    /// Asymmetric scheme to be used for key operations
    pub scheme: Option<AsymSchemeUnion>,
    /// Size of key, in bits
    pub key_bits: TPMI_RSA_KEY_BITS,
    /// Public exponent of the key. A value of 0 defaults to 2 ^ 16 + 1
    pub exponent: u32,
    /// Flag indicating whether the key shall be used for signing
    pub for_signing: bool,
    /// Flag indicating whether the key shall be used for decryption
    pub for_decryption: bool,
    /// Flag indicating whether the key is restricted
    pub restricted: bool,
}

impl TpmsRsaParmsBuilder {
    /// Create parameters for a restricted decryption key
    pub fn new_restricted_decryption_key(
        symmetric: TPMT_SYM_DEF_OBJECT,
        key_bits: TPMI_RSA_KEY_BITS,
        exponent: u32,
    ) -> Self {
        TpmsRsaParmsBuilder {
            symmetric: Some(symmetric),
            scheme: Some(AsymSchemeUnion::AnySig(None)),
            key_bits,
            exponent,
            for_signing: false,
            for_decryption: true,
            restricted: true,
        }
    }

    /// Create parameters for an unrestricted signing key
    pub fn new_unrestricted_signing_key(
        scheme: AsymSchemeUnion,
        key_bits: TPMI_RSA_KEY_BITS,
        exponent: u32,
    ) -> Self {
        TpmsRsaParmsBuilder {
            symmetric: None,
            scheme: Some(scheme),
            key_bits,
            exponent,
            for_signing: true,
            for_decryption: false,
            restricted: false,
        }
    }

    /// Build an object given the previously provded parameters.
    ///
    /// The only mandatory parameter is the asymmetric scheme.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    /// * if the `for_signing`, `for_decryption` and `restricted` parameters are
    /// inconsistent with the rest of the parameters, `InconsistentParams` wrapper
    /// error is returned
    pub fn build(self) -> Result<TPMS_RSA_PARMS> {
        if self.restricted && self.for_decryption {
            if self.symmetric.is_none() {
                return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
            }
        } else if self.symmetric.is_some() {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        let symmetric = self.symmetric.unwrap_or_else(|| TPMT_SYM_DEF_OBJECT {
            algorithm: TPM2_ALG_NULL,
            ..Default::default()
        });

        let scheme = self
            .scheme
            .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?
            .get_rsa_scheme_struct();
        if self.restricted {
            if self.for_signing
                && scheme.scheme != TPM2_ALG_RSAPSS
                && scheme.scheme != TPM2_ALG_RSASSA
            {
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }

            if self.for_decryption && scheme.scheme != TPM2_ALG_NULL {
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        } else {
            if self.for_decryption && self.for_signing && scheme.scheme != TPM2_ALG_NULL {
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
            if self.for_signing
                && scheme.scheme != TPM2_ALG_RSAPSS
                && scheme.scheme != TPM2_ALG_RSASSA
                && scheme.scheme != TPM2_ALG_NULL
            {
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }

            if self.for_decryption
                && scheme.scheme != TPM2_ALG_RSAES
                && scheme.scheme != TPM2_ALG_OAEP
                && scheme.scheme != TPM2_ALG_NULL
            {
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }
        Ok(TPMS_RSA_PARMS {
            symmetric,
            scheme,
            keyBits: self.key_bits,
            exponent: self.exponent,
        })
    }
}

/// Supported sizes for RSA key modulus
pub const RSA_KEY_SIZES: [u16; 4] = [1024, 2048, 3072, 4096];

/// Builder for `TPMS_ECC_PARMS` values.
#[derive(Copy, Clone, Debug)]
pub struct TpmsEccParmsBuilder {
    /// Symmetric cipher to be used in conjuction with the key
    pub symmetric: Option<crate::abstraction::cipher::Cipher>,
    /// Asymmetric scheme to be used for key operations
    pub scheme: AsymSchemeUnion,
    /// Curve to be used with the key
    pub curve: EllipticCurve,
    /// Flag indicating whether the key shall be used for signing
    pub for_signing: bool,
    /// Flag indicating whether the key shall be used for decryption
    pub for_decryption: bool,
    /// Flag indicating whether the key is restricted
    pub restricted: bool,
}

impl TpmsEccParmsBuilder {
    /// Create parameters for a restricted decryption key (i.e. a storage key)
    pub fn new_restricted_decryption_key(
        symmetric: crate::abstraction::cipher::Cipher,
        curve: EllipticCurve,
    ) -> Self {
        TpmsEccParmsBuilder {
            symmetric: Some(symmetric),
            scheme: AsymSchemeUnion::AnySig(None),
            curve,
            for_signing: false,
            for_decryption: true,
            restricted: true,
        }
    }

    /// Create parameters for an unrestricted signing key
    pub fn new_unrestricted_signing_key(scheme: AsymSchemeUnion, curve: EllipticCurve) -> Self {
        TpmsEccParmsBuilder {
            symmetric: None,
            scheme,
            curve,
            for_signing: true,
            for_decryption: false,
            restricted: false,
        }
    }

    /// Build an object given the previously provded parameters.
    ///
    /// The only mandatory parameters are the asymmetric scheme and the elliptic curve.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    /// * if the `for_signing`, `for_decryption` and `restricted` parameters are
    /// inconsistent with the rest of the parameters, `InconsistentParams` wrapper
    /// error is returned
    pub fn build(self) -> Result<TPMS_ECC_PARMS> {
        if self.restricted && self.for_decryption {
            if self.symmetric.is_none() {
                return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
            }
        } else if self.symmetric.is_some() {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        if self.for_decryption && self.for_signing {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        let scheme = self.scheme.get_ecc_scheme_struct();
        if self.for_signing
            && scheme.scheme != TPM2_ALG_ECDSA
            && scheme.scheme != TPM2_ALG_ECDAA
            && scheme.scheme != TPM2_ALG_SM2
            && scheme.scheme != TPM2_ALG_ECSCHNORR
        {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        if self.for_decryption
            && scheme.scheme != TPM2_ALG_SM2
            && scheme.scheme != TPM2_ALG_ECDH
            && scheme.scheme != TPM2_ALG_ECMQV
            && scheme.scheme != TPM2_ALG_NULL
        {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        if (self.curve == EllipticCurve::BnP256 || self.curve == EllipticCurve::BnP638)
            && scheme.scheme != TPM2_ALG_ECDAA
        {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        let symmetric = match self.symmetric {
            Some(symmetric) => symmetric.into(),
            None => TPMT_SYM_DEF_OBJECT {
                algorithm: TPM2_ALG_NULL,
                ..Default::default()
            },
        };

        Ok(TPMS_ECC_PARMS {
            symmetric,
            scheme,
            curveID: self.curve.into(),
            kdf: TPMT_KDF_SCHEME {
                scheme: TPM2_ALG_NULL,
                details: Default::default(),
            },
        })
    }
}

/// Builder for `TPMT_SYM_DEF` objects.
#[derive(Copy, Clone, Debug)]
pub struct TpmtSymDefBuilder {
    algorithm: Option<TPM2_ALG_ID>,
    key_bits: u16,
    mode: TPM2_ALG_ID,
}

impl TpmtSymDefBuilder {
    /// Create a new builder with default (i.e. empty or null) placeholder values.
    pub fn new() -> Self {
        TpmtSymDefBuilder {
            algorithm: None,
            key_bits: 0,
            mode: TPM2_ALG_NULL,
        }
    }

    /// Set the symmetric algorithm.
    pub fn with_algorithm(mut self, algorithm: TPM2_ALG_ID) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set the key length.
    pub fn with_key_bits(mut self, key_bits: TPM2_KEY_BITS) -> Self {
        self.key_bits = key_bits;
        self
    }

    /// Set the hash algorithm (applies when the symmetric algorithm is XOR).
    pub fn with_hash(mut self, hash: TPM2_ALG_ID) -> Self {
        self.key_bits = hash;
        self
    }

    /// Set the mode of the symmetric algorithm.
    pub fn with_mode(mut self, mode: TPM2_ALG_ID) -> Self {
        self.mode = mode;
        self
    }

    /// Build a TPMT_SYM_DEF given the previously provided parameters.
    ///
    /// # Errors
    /// * if an unrecognized symmetric algorithm type was set, `UnsupportedParam` wrapper error
    /// is returned.
    /// * if an algorithm is not explicitly set, `ParamsMissing` is returned
    pub fn build(self) -> Result<TPMT_SYM_DEF> {
        let (key_bits, mode) = self.bits_and_mode()?;

        Ok(TPMT_SYM_DEF {
            algorithm: self.algorithm.unwrap(), // bits_and_mode would return an Err if algorithm was missing
            keyBits: key_bits,
            mode,
        })
    }

    /// Build a TPMT_SYM_DEF_OBJECT given the previously provided parameters.
    ///
    /// # Errors
    /// * if an unrecognized symmetric algorithm type was set, `UnsupportedParam` wrapper error
    /// is returned.
    /// * if an algorithm is not explicitly set, `ParamsMissing` is returned
    pub fn build_object(self) -> Result<TPMT_SYM_DEF_OBJECT> {
        let (key_bits, mode) = self.bits_and_mode()?;

        Ok(TPMT_SYM_DEF_OBJECT {
            algorithm: self.algorithm.unwrap(), // bits_and_mode would return an Err if algorithm was missing
            keyBits: key_bits,
            mode,
        })
    }

    fn bits_and_mode(self) -> Result<(TPMU_SYM_KEY_BITS, TPMU_SYM_MODE)> {
        let key_bits;
        let mode;
        match self.algorithm {
            Some(TPM2_ALG_XOR) => {
                // Exclusive OR
                key_bits = TPMU_SYM_KEY_BITS {
                    exclusiveOr: self.key_bits,
                };
                mode = Default::default(); // NULL
            }
            Some(TPM2_ALG_AES) => {
                // AES
                key_bits = TPMU_SYM_KEY_BITS { aes: self.key_bits };
                mode = TPMU_SYM_MODE { aes: self.mode };
            }
            Some(TPM2_ALG_SM4) => {
                // SM4
                key_bits = TPMU_SYM_KEY_BITS { sm4: self.key_bits };
                mode = TPMU_SYM_MODE { sm4: self.mode };
            }
            Some(TPM2_ALG_CAMELLIA) => {
                // CAMELLIA
                key_bits = TPMU_SYM_KEY_BITS {
                    camellia: self.key_bits,
                };
                mode = TPMU_SYM_MODE {
                    camellia: self.mode,
                };
            }
            Some(TPM2_ALG_NULL) => {
                // NULL
                key_bits = Default::default();
                mode = Default::default();
            }
            None => return Err(Error::local_error(WrapperErrorKind::ParamsMissing)),
            _ => return Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }

        Ok((key_bits, mode))
    }
}

impl Default for TpmtSymDefBuilder {
    fn default() -> Self {
        TpmtSymDefBuilder::new()
    }
}

/// Rust enum representation of `TPMU_PUBLIC_ID`.
// Most of the field types are from bindgen which does not implement Debug on them.
#[allow(missing_debug_implementations)]
pub enum PublicIdUnion {
    KeyedHash(TPM2B_DIGEST),
    Sym(TPM2B_DIGEST),
    Rsa(Box<TPM2B_PUBLIC_KEY_RSA>),
    Ecc(Box<TPMS_ECC_POINT>),
}

impl PublicIdUnion {
    /// Extract a `PublicIdUnion` from a `TPM2B_PUBLIC` object.
    ///
    /// # Constraints
    /// * the value of `public.publicArea.type_` *MUST* be consistent with the union field used in
    /// `public.publicArea.unique`.
    ///
    /// # Safety
    ///
    /// Check "Notes on code safety" section in the crate-level documentation.
    pub unsafe fn from_public(public: &TPM2B_PUBLIC) -> Result<Self> {
        match public.publicArea.type_ {
            TPM2_ALG_RSA => Ok(PublicIdUnion::Rsa(Box::from(public.publicArea.unique.rsa))),
            TPM2_ALG_ECC => Ok(PublicIdUnion::Ecc(Box::from(public.publicArea.unique.ecc))),
            TPM2_ALG_SYMCIPHER => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_KEYEDHASH => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

/// Rust enum representation of `TPMU_PUBLIC_PARMS`.
// Most of the field types are from bindgen which does not implement Debug on them.
#[allow(missing_debug_implementations)]
#[allow(clippy::pub_enum_variant_names)]
#[derive(Copy, Clone)]
pub enum PublicParmsUnion {
    KeyedHashDetail(KeyedHashParms),
    SymDetail(crate::abstraction::cipher::Cipher),
    RsaDetail(TPMS_RSA_PARMS),
    EccDetail(TPMS_ECC_PARMS),
    AsymDetail(TPMS_ASYM_PARMS),
}

impl PublicParmsUnion {
    /// Get the object type corresponding to the value's variant.
    pub fn object_type(&self) -> TPMI_ALG_PUBLIC {
        match self {
            PublicParmsUnion::AsymDetail(..) => TPM2_ALG_NULL,
            PublicParmsUnion::EccDetail(..) => TPM2_ALG_ECC,
            PublicParmsUnion::RsaDetail(..) => TPM2_ALG_RSA,
            PublicParmsUnion::SymDetail(..) => TPM2_ALG_SYMCIPHER,
            PublicParmsUnion::KeyedHashDetail(..) => TPM2_ALG_KEYEDHASH,
        }
    }
}

impl From<PublicParmsUnion> for TPMU_PUBLIC_PARMS {
    fn from(parms: PublicParmsUnion) -> Self {
        match parms {
            PublicParmsUnion::AsymDetail(tss_parms) => TPMU_PUBLIC_PARMS {
                asymDetail: tss_parms,
            },
            PublicParmsUnion::EccDetail(tss_parms) => TPMU_PUBLIC_PARMS {
                eccDetail: tss_parms,
            },
            PublicParmsUnion::RsaDetail(tss_parms) => TPMU_PUBLIC_PARMS {
                rsaDetail: tss_parms,
            },
            PublicParmsUnion::SymDetail(cipher) => TPMU_PUBLIC_PARMS {
                symDetail: cipher.into(),
            },
            PublicParmsUnion::KeyedHashDetail(tss_parms) => TPMU_PUBLIC_PARMS {
                keyedHashDetail: tss_parms.into(),
            },
        }
    }
}

/// Rust enum representation of `TPMU_ASYM_SCHEME`.
#[derive(Copy, Clone, Debug)]
pub enum AsymSchemeUnion {
    ECDH(HashingAlgorithm),
    ECMQV(HashingAlgorithm),
    RSASSA(HashingAlgorithm),
    RSAPSS(HashingAlgorithm),
    ECDSA(HashingAlgorithm),
    ECDAA(HashingAlgorithm, u16),
    SM2(HashingAlgorithm),
    ECSchnorr(HashingAlgorithm),
    RSAES,
    RSAOAEP(HashingAlgorithm),
    AnySig(Option<HashingAlgorithm>),
}

impl AsymSchemeUnion {
    /// Get scheme ID.
    pub fn scheme_id(self) -> TPM2_ALG_ID {
        match self {
            AsymSchemeUnion::ECDH(_) => TPM2_ALG_ECDH,
            AsymSchemeUnion::ECMQV(_) => TPM2_ALG_ECMQV,
            AsymSchemeUnion::RSASSA(_) => TPM2_ALG_RSASSA,
            AsymSchemeUnion::RSAPSS(_) => TPM2_ALG_RSAPSS,
            AsymSchemeUnion::ECDSA(_) => TPM2_ALG_ECDSA,
            AsymSchemeUnion::ECDAA(_, _) => TPM2_ALG_ECDAA,
            AsymSchemeUnion::SM2(_) => TPM2_ALG_SM2,
            AsymSchemeUnion::ECSchnorr(_) => TPM2_ALG_ECSCHNORR,
            AsymSchemeUnion::RSAES => TPM2_ALG_RSAES,
            AsymSchemeUnion::RSAOAEP(_) => TPM2_ALG_OAEP,
            AsymSchemeUnion::AnySig(_) => TPM2_ALG_NULL,
        }
    }

    fn get_details(self) -> TPMU_ASYM_SCHEME {
        match self {
            AsymSchemeUnion::ECDH(hash_alg) => TPMU_ASYM_SCHEME {
                ecdh: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::ECMQV(hash_alg) => TPMU_ASYM_SCHEME {
                ecmqv: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::RSASSA(hash_alg) => TPMU_ASYM_SCHEME {
                rsassa: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::RSAPSS(hash_alg) => TPMU_ASYM_SCHEME {
                rsapss: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::ECDSA(hash_alg) => TPMU_ASYM_SCHEME {
                ecdsa: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::ECDAA(hash_alg, count) => TPMU_ASYM_SCHEME {
                ecdaa: TPMS_SCHEME_ECDAA {
                    hashAlg: hash_alg.into(),
                    count,
                },
            },
            AsymSchemeUnion::SM2(hash_alg) => TPMU_ASYM_SCHEME {
                sm2: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::ECSchnorr(hash_alg) => TPMU_ASYM_SCHEME {
                ecschnorr: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::RSAES => TPMU_ASYM_SCHEME {
                rsaes: Default::default(),
            },
            AsymSchemeUnion::RSAOAEP(hash_alg) => TPMU_ASYM_SCHEME {
                oaep: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.into(),
                },
            },
            AsymSchemeUnion::AnySig(hash_alg) => TPMU_ASYM_SCHEME {
                anySig: TPMS_SCHEME_HASH {
                    hashAlg: hash_alg.map(u16::from).or(Some(TPM2_ALG_NULL)).unwrap(),
                },
            },
        }
    }

    /// Convert scheme object to `TPMT_RSA_SCHEME`.
    fn get_rsa_scheme_struct(self) -> TPMT_RSA_SCHEME {
        let scheme = self.scheme_id();
        let details = self.get_details();

        TPMT_RSA_SCHEME { scheme, details }
    }

    /// Convert scheme object to `TPMT_RSA_DECRYPT`.
    pub fn get_rsa_decrypt_struct(self) -> TPMT_RSA_DECRYPT {
        let scheme = self.scheme_id();
        let details = self.get_details();

        TPMT_RSA_DECRYPT { scheme, details }
    }

    /// Convert scheme object to `TPMT_ECC_SCHEME`.
    fn get_ecc_scheme_struct(self) -> TPMT_ECC_SCHEME {
        let scheme = self.scheme_id();
        let details = self.get_details();

        TPMT_ECC_SCHEME { scheme, details }
    }

    pub fn is_signing(self) -> bool {
        match self {
            AsymSchemeUnion::ECDH(_)
            | AsymSchemeUnion::ECMQV(_)
            | AsymSchemeUnion::RSAOAEP(_)
            | AsymSchemeUnion::RSAES => false,
            AsymSchemeUnion::RSASSA(_)
            | AsymSchemeUnion::RSAPSS(_)
            | AsymSchemeUnion::ECDSA(_)
            | AsymSchemeUnion::ECDAA(_, _)
            | AsymSchemeUnion::SM2(_)
            | AsymSchemeUnion::ECSchnorr(_)
            | AsymSchemeUnion::AnySig(_) => true,
        }
    }

    pub fn is_decryption(self) -> bool {
        match self {
            AsymSchemeUnion::ECDH(_)
            | AsymSchemeUnion::ECMQV(_)
            | AsymSchemeUnion::RSAOAEP(_)
            | AsymSchemeUnion::RSAES => true,
            AsymSchemeUnion::RSASSA(_)
            | AsymSchemeUnion::RSAPSS(_)
            | AsymSchemeUnion::ECDSA(_)
            | AsymSchemeUnion::ECDAA(_, _)
            | AsymSchemeUnion::SM2(_)
            | AsymSchemeUnion::ECSchnorr(_)
            | AsymSchemeUnion::AnySig(_) => false,
        }
    }

    pub fn is_rsa(self) -> bool {
        match self {
            AsymSchemeUnion::RSASSA(_)
            | AsymSchemeUnion::RSAOAEP(_)
            | AsymSchemeUnion::RSAPSS(_)
            | AsymSchemeUnion::AnySig(_)
            | AsymSchemeUnion::RSAES => true,
            AsymSchemeUnion::ECDH(_)
            | AsymSchemeUnion::ECMQV(_)
            | AsymSchemeUnion::ECDSA(_)
            | AsymSchemeUnion::ECDAA(_, _)
            | AsymSchemeUnion::SM2(_)
            | AsymSchemeUnion::ECSchnorr(_) => false,
        }
    }

    pub fn is_ecc(self) -> bool {
        match self {
            AsymSchemeUnion::RSASSA(_)
            | AsymSchemeUnion::RSAOAEP(_)
            | AsymSchemeUnion::RSAPSS(_)
            | AsymSchemeUnion::AnySig(_)
            | AsymSchemeUnion::RSAES => false,
            AsymSchemeUnion::ECDH(_)
            | AsymSchemeUnion::ECMQV(_)
            | AsymSchemeUnion::ECDSA(_)
            | AsymSchemeUnion::ECDAA(_, _)
            | AsymSchemeUnion::SM2(_)
            | AsymSchemeUnion::ECSchnorr(_) => true,
        }
    }
}

/// Rust native representation of an asymmetric signature.
///
/// The structure contains the signature as a byte vector and the scheme with which the signature
/// was created.
#[derive(Debug)]
pub struct Signature {
    pub scheme: AsymSchemeUnion,
    pub signature: SignatureData,
}

#[derive(Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub enum SignatureData {
    RsaSignature(Vec<u8>),
    EcdsaSignature { r: Vec<u8>, s: Vec<u8> },
}

impl Signature {
    /// Attempt to parse a signature from a `TPMT_SIGNATURE` object.
    ///
    /// # Constraints
    /// * the value of `tss_signature.sigAlg` *MUST* be consistent with the union field used in
    /// `tss_signature.signature`
    ///
    /// # Safety
    ///
    /// Check "Notes on code safety" section in the crate-level documentation.
    pub unsafe fn try_from(tss_signature: TPMT_SIGNATURE) -> Result<Self> {
        match tss_signature.sigAlg {
            TPM2_ALG_RSASSA => {
                let hash_alg = tss_signature.signature.rsassa.hash;
                let scheme = AsymSchemeUnion::RSASSA(hash_alg.try_into()?);
                let signature_buf = tss_signature.signature.rsassa.sig;
                let mut signature = signature_buf.buffer.to_vec();
                let buf_size = signature_buf.size.into();
                if buf_size > signature.len() {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                signature.truncate(buf_size);

                Ok(Signature {
                    scheme,
                    signature: SignatureData::RsaSignature(signature),
                })
            }
            TPM2_ALG_RSAPSS => {
                let hash_alg = tss_signature.signature.rsapss.hash;
                let scheme = AsymSchemeUnion::RSAPSS(hash_alg.try_into()?);
                let signature_buf = tss_signature.signature.rsassa.sig;
                let mut signature = signature_buf.buffer.to_vec();
                let buf_size = signature_buf.size.into();
                if buf_size > signature.len() {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                signature.truncate(buf_size);

                Ok(Signature {
                    scheme,
                    signature: SignatureData::RsaSignature(signature),
                })
            }
            TPM2_ALG_ECDSA => {
                let hash_alg = tss_signature.signature.ecdsa.hash;
                let scheme = AsymSchemeUnion::ECDSA(hash_alg.try_into()?);
                let buf = tss_signature.signature.ecdsa.signatureR;
                let mut r = buf.buffer.to_vec();
                let buf_size = buf.size.into();
                if buf_size > r.len() {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                r.truncate(buf_size);

                let buf = tss_signature.signature.ecdsa.signatureS;
                let mut s = buf.buffer.to_vec();
                let buf_size = buf.size.into();
                if buf_size > s.len() {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                s.truncate(buf_size);

                Ok(Signature {
                    scheme,
                    signature: SignatureData::EcdsaSignature { r, s },
                })
            }
            TPM2_ALG_SM2 | TPM2_ALG_ECSCHNORR | TPM2_ALG_ECDAA => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

impl TryFrom<Signature> for TPMT_SIGNATURE {
    type Error = Error;
    fn try_from(sig: Signature) -> Result<Self> {
        if sig.scheme.is_decryption() {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }
        match sig.scheme {
            AsymSchemeUnion::RSASSA(hash_alg) => {
                let signature = match sig.signature {
                    SignatureData::RsaSignature(signature) => signature,
                    SignatureData::EcdsaSignature { .. } => {
                        return Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                    }
                };

                let len = signature.len();
                if len > 512 {
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }

                let mut buffer = [0_u8; 512];
                buffer[..len].clone_from_slice(&signature[..len]);
                Ok(TPMT_SIGNATURE {
                    sigAlg: TPM2_ALG_RSASSA,
                    signature: TPMU_SIGNATURE {
                        rsassa: TPMS_SIGNATURE_RSA {
                            hash: hash_alg.into(),
                            sig: TPM2B_PUBLIC_KEY_RSA {
                                size: len.try_into().expect("Failed to convert length to u16"), // Should never panic as per the check above
                                buffer,
                            },
                        },
                    },
                })
            }
            AsymSchemeUnion::RSAPSS(hash_alg) => {
                let signature = match sig.signature {
                    SignatureData::RsaSignature(signature) => signature,
                    SignatureData::EcdsaSignature { .. } => {
                        return Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                    }
                };

                let len = signature.len();
                if len > 512 {
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }

                let mut buffer = [0_u8; 512];
                buffer[..len].clone_from_slice(&signature[..len]);
                Ok(TPMT_SIGNATURE {
                    sigAlg: TPM2_ALG_RSAPSS,
                    signature: TPMU_SIGNATURE {
                        rsapss: TPMS_SIGNATURE_RSA {
                            hash: hash_alg.into(),
                            sig: TPM2B_PUBLIC_KEY_RSA {
                                size: len.try_into().expect("Failed to convert length to u16"), // Should never panic as per the check above
                                buffer,
                            },
                        },
                    },
                })
            }
            AsymSchemeUnion::ECDSA(hash_alg) => {
                let signature = match sig.signature {
                    SignatureData::EcdsaSignature { r, s } => (r, s),
                    SignatureData::RsaSignature(_) => {
                        return Err(Error::local_error(WrapperErrorKind::InconsistentParams))
                    }
                };

                let r_len = signature.0.len();
                if r_len > 128 {
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }

                let mut r_buffer = [0_u8; 128];
                r_buffer[..r_len].clone_from_slice(&signature.0[..r_len]);

                let s_len = signature.1.len();
                if s_len > 128 {
                    return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
                }

                let mut s_buffer = [0_u8; 128];
                s_buffer[..s_len].clone_from_slice(&signature.1[..s_len]);

                Ok(TPMT_SIGNATURE {
                    sigAlg: TPM2_ALG_ECDSA,
                    signature: TPMU_SIGNATURE {
                        ecdsa: TPMS_SIGNATURE_ECDSA {
                            hash: hash_alg.into(),
                            signatureR: TPM2B_ECC_PARAMETER {
                                size: r_len.try_into().expect("Failed to convert length to u16"), // Should never panic as per the check above
                                buffer: r_buffer,
                            },
                            signatureS: TPM2B_ECC_PARAMETER {
                                size: s_len.try_into().expect("Failed to convert length to u16"), // Should never panic as per the check above
                                buffer: s_buffer,
                            },
                        },
                    },
                })
            }
            _ => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
        }
    }
}

/// Rust native wrapper for `TPMS_CONTEXT` objects.
///
/// This structure is intended to help with persisting object contexts. As the main reason for
/// saving the context of an object is to be able to re-use it later, on demand, a serializable
/// structure is most commonly needed. `TpmsContext` implements the `Serialize` and `Deserialize`
/// defined by `serde`.
#[derive(Debug, Serialize, Deserialize, Clone, Zeroize)]
#[zeroize(drop)]
pub struct TpmsContext {
    sequence: u64,
    saved_handle: TPMI_DH_CONTEXT,
    hierarchy: TPMI_RH_HIERARCHY,
    context_blob: Vec<u8>,
}

// TODO: Replace with `From`
impl TryFrom<TPMS_CONTEXT> for TpmsContext {
    type Error = Error;

    fn try_from(tss2_context: TPMS_CONTEXT) -> Result<Self> {
        let mut context = TpmsContext {
            sequence: tss2_context.sequence,
            saved_handle: tss2_context.savedHandle,
            hierarchy: tss2_context.hierarchy,
            context_blob: tss2_context.contextBlob.buffer.to_vec(),
        };
        context.context_blob.truncate(
            tss2_context
                .contextBlob
                .size
                .try_into()
                .map_err(|_| Error::local_error(WrapperErrorKind::WrongParamSize))?,
        );
        Ok(context)
    }
}

#[allow(clippy::needless_update)]
impl TryFrom<TpmsContext> for TPMS_CONTEXT {
    type Error = Error;

    fn try_from(context: TpmsContext) -> Result<Self> {
        let buffer_size = context.context_blob.len();
        if buffer_size > 5188 {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }
        let mut buffer = [0_u8; 5188];
        for (i, val) in context.context_blob.iter().enumerate() {
            buffer[i] = *val;
        }
        Ok(TPMS_CONTEXT {
            sequence: context.sequence,
            savedHandle: context.saved_handle,
            hierarchy: context.hierarchy,
            contextBlob: TPM2B_CONTEXT_DATA {
                size: buffer_size.try_into().unwrap(), // should not panic given the check above
                buffer,
            },
            ..Default::default()
        })
    }
}

/// Create the TPM2B_PUBLIC structure for a restricted decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key. A value of 0 defaults to 2^16 + 1
pub fn create_restricted_decryption_rsa_public(
    symmetric: crate::abstraction::cipher::Cipher,
    key_bits: u16,
    pub_exponent: u32,
) -> Result<TPM2B_PUBLIC> {
    let rsa_parms = TpmsRsaParmsBuilder::new_restricted_decryption_key(
        symmetric.into(),
        key_bits,
        pub_exponent,
    )
    .build()?;

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(false)
        .with_restricted(true)
        .build()?;

    Tpm2BPublicBuilder::new()
        .with_type(TPM2_ALG_RSA)
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
        .build()
}

/// Create the TPM2B_PUBLIC structure for an unrestricted encryption/decryption key.
///
/// * `symmetric` - Cipher to be used for decrypting children of the key
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key. A value of 0 defaults to 2^16 + 1
pub fn create_unrestricted_encryption_decryption_rsa_public(
    key_bits: u16,
    pub_exponent: u32,
) -> Result<TPM2B_PUBLIC> {
    let rsa_parms = TpmsRsaParmsBuilder {
        symmetric: None,
        scheme: Some(AsymSchemeUnion::AnySig(None)),
        key_bits,
        exponent: pub_exponent,
        for_signing: true,
        for_decryption: true,
        restricted: false,
    }
    .build()
    .unwrap();

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(true)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    Tpm2BPublicBuilder::new()
        .with_type(TPM2_ALG_RSA)
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
        .build()
}

/// Create the TPM2B_PUBLIC structure for an RSA unrestricted signing key.
///
/// * `scheme` - Asymmetric scheme to be used for signing
/// * `key_bits` - Size in bits of the decryption key
/// * `pub_exponent` - Public exponent of the RSA key. A value of 0 defaults to 2^16 + 1
pub fn create_unrestricted_signing_rsa_public(
    scheme: AsymSchemeUnion,
    key_bits: u16,
    pub_exponent: u32,
) -> Result<TPM2B_PUBLIC> {
    let rsa_parms =
        TpmsRsaParmsBuilder::new_unrestricted_signing_key(scheme, key_bits, pub_exponent)
            .build()?;

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    Tpm2BPublicBuilder::new()
        .with_type(TPM2_ALG_RSA)
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
        .build()
}

/// Create the TPM2B_PUBLIC structure for an ECC unrestricted signing key.
///
/// * `scheme` - Asymmetric scheme to be used for signing; *must* be an RSA signing scheme
/// * `curve` - identifier of the precise curve to be used with the key
pub fn create_unrestricted_signing_ecc_public(
    scheme: AsymSchemeUnion,
    curve: EllipticCurve,
) -> Result<TPM2B_PUBLIC> {
    let ecc_parms = TpmsEccParmsBuilder::new_unrestricted_signing_key(scheme, curve).build()?;

    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;

    Tpm2BPublicBuilder::new()
        .with_type(TPM2_ALG_ECC)
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(PublicParmsUnion::EccDetail(ecc_parms))
        .build()
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    Rsa(Vec<u8>),
    Ecc { x: Vec<u8>, y: Vec<u8> },
}

type PcrValue = Digest;

/// Struct for holding PcrSlots and their
/// corresponding values.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PcrBank {
    bank: BTreeMap<PcrSlot, PcrValue>,
}

impl PcrBank {
    /// Function for retrieving a pcr value corresponding to a pcr slot.
    pub fn pcr_value(&self, pcr_slot: PcrSlot) -> Option<&PcrValue> {
        self.bank.get(&pcr_slot)
    }

    /// Function for retrieiving the number of pcr slot values in the bank.
    pub fn len(&self) -> usize {
        self.bank.len()
    }

    /// Returns true if there are no pcr slot values in the bank.
    pub fn is_empty(&self) -> bool {
        self.bank.is_empty()
    }
}

impl<'a> IntoIterator for &'a PcrBank {
    type Item = (&'a PcrSlot, &'a PcrValue);
    type IntoIter = ::std::collections::btree_map::Iter<'a, PcrSlot, PcrValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.bank.iter()
    }
}

/// Struct holding pcr banks and their associated
/// hashing algorithm
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrData {
    data: HashMap<HashingAlgorithm, PcrBank>,
}

impl PcrData {
    /// Contrustctor that creates a PcrData from
    /// tss types.
    pub fn new(
        tpml_pcr_selections: &TPML_PCR_SELECTION,
        tpml_digests: &TPML_DIGEST,
    ) -> Result<Self> {
        // Check digests
        let digests_count = tpml_digests.count as usize;
        if digests_count > 8 {
            error!("Error: Invalid TPML_DIGEST count(> 8)");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        let digests = &tpml_digests.digests[..digests_count];
        // Check selections
        let selections_count = tpml_pcr_selections.count as usize;
        if selections_count > 16 {
            error!("Error: Invalid TPML_SELECTIONS count(> 16)");
            return Err(Error::local_error(WrapperErrorKind::InvalidParam));
        }
        let pcr_selections = &tpml_pcr_selections.pcrSelections[..selections_count];

        let mut digest_iter = digests.iter();
        let mut parsed_pcr_data = PcrData {
            data: Default::default(),
        };
        for &pcr_selection in pcr_selections {
            // Parse hash algorithm from selection
            let parsed_hash_algorithm =
                HashingAlgorithm::try_from(pcr_selection.hash).map_err(|e| {
                    error!("Error converting hash to a HashingAlgorithm: {}", e);
                    Error::local_error(WrapperErrorKind::InvalidParam)
                })?;
            // Parse pcr slots from selection
            let parsed_pcr_slots: BitFlags<PcrSlot> =
                BitFlags::<PcrSlot>::try_from(u32::from_le_bytes(pcr_selection.pcrSelect))
                    .map_err(|e| {
                        error!("Error parsing pcrSelect to a BitFlags<PcrSlot>: {}", e);
                        Error::local_error(WrapperErrorKind::UnsupportedParam)
                    })?;
            // Create PCR bank by mapping the pcr slots to the pcr values
            let mut parsed_pcr_bank = PcrBank {
                bank: Default::default(),
            };
            for pcr_slot in parsed_pcr_slots.iter() {
                // Make sure there are still data
                let digest = match digest_iter.next() {
                    Some(val) => val,
                    None => {
                        error!("Error number of items in selection does not match number of items in data");
                        return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                    }
                };
                // Add the value corresponding to the pcr slot.
                if parsed_pcr_bank
                    .bank
                    .insert(pcr_slot, PcrValue::try_from(*digest)?)
                    .is_some()
                {
                    error!("Error trying to insert data into PcrSlot where data have already been inserted");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
            }
            // Add the parsed pcr bank for the parsed hashing algorithm.
            if parsed_pcr_data
                .data
                .insert(parsed_hash_algorithm, parsed_pcr_bank)
                .is_some()
            {
                error!("Error trying to insert data into a PcrBank where data have already been inserted");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }
        // Make sure all values in the digest have been read.
        if digest_iter.next().is_some() {
            error!("Error not all values in the digest have been handled");
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        Ok(parsed_pcr_data)
    }
    /// Function for retriving a bank associated with the hashing_algorithm.
    pub fn pcr_bank(&self, hashing_algorithm: HashingAlgorithm) -> Option<&PcrBank> {
        self.data.get(&hashing_algorithm)
    }

    /// Function for retrieving the number of banks in the data.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no banks in the data.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl<'a> IntoIterator for &'a PcrData {
    type Item = (&'a HashingAlgorithm, &'a PcrBank);
    type IntoIter = ::std::collections::hash_map::Iter<'a, HashingAlgorithm, PcrBank>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.iter()
    }
}

impl From<PcrData> for TPML_DIGEST {
    fn from(pcr_data: PcrData) -> Self {
        let mut tpml_digest: TPML_DIGEST = Default::default();

        for (_hash_algo, pcr_bank) in pcr_data.into_iter() {
            for (_pcr_slot, pcr_value) in pcr_bank.into_iter() {
                let i = tpml_digest.count as usize;
                let size = pcr_value.value().len() as u16;
                tpml_digest.digests[i].size = size;
                tpml_digest.digests[i].buffer[..size as usize].copy_from_slice(pcr_value.value());
                tpml_digest.count += 1;
            }
        }
        tpml_digest
    }
}

fn tpm_int_to_string(num: u32) -> String {
    num.to_be_bytes()
        .iter()
        .filter(|x| **x != 0)
        .map(|x| char::from(*x))
        .collect()
}

/// Get the TPM vendor name
pub fn get_tpm_vendor(context: &mut Context) -> Result<String> {
    // Retrieve the TPM property values
    Ok([
        PropertyTag::VendorString1,
        PropertyTag::VendorString2,
        PropertyTag::VendorString3,
        PropertyTag::VendorString4,
    ]
    .iter()
    // Retrieve property values
    .map(|propid| context.get_tpm_property(*propid))
    // Collect and return an error if we got one
    .collect::<Result<Vec<Option<u32>>>>()?
    .iter()
    // Filter out the Option::None values
    .filter_map(|x| *x)
    // Filter out zero values
    .filter(|x| *x != 0)
    // Map through int_to_string
    .map(tpm_int_to_string)
    // Collect to a single string
    .collect())
}
