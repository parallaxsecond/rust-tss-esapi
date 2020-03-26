// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Utility module
//!
//! This module mostly contains helper elements meant to act as either wrappers around FFI-level
//! structs or builders for them, along with other convenience elements.
//! The naming structure usually takes the names inherited from the TSS spec and applies Rust
//! guidelines to them. Structures that are meant to act as builders have `Builder` appended to
//! type name. Unions are converted to Rust `enum`s by dropping the `TPMU` qualifier and appending
//! `Union`.
pub mod algorithm_specifiers;

use crate::constants::*;
use crate::response_code::{Error, Result, WrapperErrorKind};
use crate::tss2_esys::*;
use algorithm_specifiers::Cipher;
use bitfield::bitfield;
use serde::{Deserialize, Serialize};
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
    pub fn build(mut self) -> Result<TPM2B_PUBLIC> {
        match self.type_ {
            Some(TPM2_ALG_RSA) => {
                // RSA key
                let mut parameters;
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

                if self.object_attributes.sign_encrypt() && self.object_attributes.decrypt() {
                    self.object_attributes.set_restricted(false);
                }

                // the checks around the scheme definition could be improved/expanded
                if self.object_attributes.decrypt() && self.object_attributes.restricted() {
                    parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
                    parameters.rsaDetail.scheme.details = TPMU_ASYM_SCHEME {
                        anySig: TPMS_SCHEME_HASH {
                            hashAlg: TPM2_ALG_NULL,
                        },
                    };
                }

                if !(self.object_attributes.decrypt() && self.object_attributes.restricted()) {
                    parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
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
    symmetric: TPMT_SYM_DEF_OBJECT,
    scheme: Option<AsymSchemeUnion>,
    key_bits: TPMI_RSA_KEY_BITS,
    exponent: u32,
}

impl TpmsRsaParmsBuilder {
    /// Create a new builder with default (i.e. empty or null) placeholder values.
    pub fn new() -> Self {
        let mut builder = TpmsRsaParmsBuilder {
            symmetric: Default::default(),
            scheme: None,
            key_bits: 2048,
            exponent: 0,
        };
        builder.symmetric.algorithm = TPM2_ALG_NULL;

        builder
    }

    /// Set the symmetric algorithm for parameter encryption.
    pub fn with_symmetric(mut self, symmetric: TPMT_SYM_DEF_OBJECT) -> Self {
        self.symmetric = symmetric;
        self
    }

    /// Set the asymmetric scheme for the object.
    pub fn with_scheme(mut self, scheme: AsymSchemeUnion) -> Self {
        self.scheme = Some(scheme);
        self
    }

    /// Set the size of the key in bits.
    pub fn with_key_bits(mut self, key_bits: TPMI_RSA_KEY_BITS) -> Self {
        self.key_bits = key_bits;
        self
    }

    /// Set the RSA exponent.
    pub fn with_exponent(mut self, exponent: u32) -> Self {
        self.exponent = exponent;
        self
    }

    /// Build an object given the previously provded parameters.
    ///
    /// The only mandatory parameter is the asymmetric scheme.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    pub fn build(self) -> Result<TPMS_RSA_PARMS> {
        Ok(TPMS_RSA_PARMS {
            symmetric: self.symmetric,
            scheme: self
                .scheme
                .ok_or_else(|| Error::local_error(WrapperErrorKind::ParamsMissing))?
                .get_rsa_scheme(),
            keyBits: self.key_bits,
            exponent: self.exponent,
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

    /// Generate a `TPMT_SYM_DEF` object defining 256 bit AES in CFB mode.
    pub fn aes_256_cfb() -> TPMT_SYM_DEF {
        TPMT_SYM_DEF {
            algorithm: TPM2_ALG_AES,
            keyBits: TPMU_SYM_KEY_BITS { aes: 256 },
            mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
        }
    }

    /// Generate a `TPMT_SYM_DEF_OBJECT` object defining 256 bit AES in CFB mode.
    pub fn aes_256_cfb_object() -> TPMT_SYM_DEF_OBJECT {
        TPMT_SYM_DEF_OBJECT {
            algorithm: TPM2_ALG_AES,
            keyBits: TPMU_SYM_KEY_BITS { aes: 256 },
            mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
        }
    }
}

impl Default for TpmtSymDefBuilder {
    fn default() -> Self {
        TpmtSymDefBuilder::new()
    }
}

bitfield! {
    pub struct ObjectAttributes(TPMA_OBJECT);
    impl Debug;
    // Object attribute flags
    pub fixed_tpm, set_fixed_tpm: 1;
    pub st_clear, set_st_clear: 2;
    pub fixed_parent, set_fixed_parent: 4;
    pub sensitive_data_origin, set_sensitive_data_origin: 5;
    pub user_with_auth, set_user_with_auth: 6;
    pub admin_with_policy, set_admin_with_policy: 7;
    pub no_da, set_no_da: 10;
    pub encrypted_duplication, set_encrypted_duplication: 11;
    pub restricted, set_restricted: 16;
    pub decrypt, set_decrypt: 17;
    pub sign_encrypt, set_sign_encrypt: 18;
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
            TPM2_ALG_ECC => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
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
    KeyedHashDetail(TPMS_KEYEDHASH_PARMS),
    SymDetail(Cipher),
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
                keyedHashDetail: tss_parms,
            },
        }
    }
}

/// Rust enum representation of `TPMU_ASYM_SCHEME`.
#[derive(Copy, Clone, Debug)]
pub enum AsymSchemeUnion {
    ECDH(TPMI_ALG_HASH),
    ECMQV(TPMI_ALG_HASH),
    RSASSA(TPMI_ALG_HASH),
    RSAPSS(TPMI_ALG_HASH),
    ECDSA(TPMI_ALG_HASH),
    ECDAA(TPMI_ALG_HASH, u16),
    SM2(TPMI_ALG_HASH),
    ECSchnorr(TPMI_ALG_HASH),
    RSAES,
    RSAOAEP(TPMI_ALG_HASH),
    AnySig(TPMI_ALG_HASH),
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

    /// Convert scheme object to `TPMT_RSA_SCHEME`.
    fn get_rsa_scheme(self) -> TPMT_RSA_SCHEME {
        let scheme = self.scheme_id();
        let details = match self {
            AsymSchemeUnion::ECDH(hash_alg) => TPMU_ASYM_SCHEME {
                ecdh: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::ECMQV(hash_alg) => TPMU_ASYM_SCHEME {
                ecmqv: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::RSASSA(hash_alg) => TPMU_ASYM_SCHEME {
                rsassa: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::RSAPSS(hash_alg) => TPMU_ASYM_SCHEME {
                rsapss: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::ECDSA(hash_alg) => TPMU_ASYM_SCHEME {
                ecdsa: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::ECDAA(hash_alg, count) => TPMU_ASYM_SCHEME {
                ecdaa: TPMS_SCHEME_ECDAA {
                    hashAlg: hash_alg,
                    count,
                },
            },
            AsymSchemeUnion::SM2(hash_alg) => TPMU_ASYM_SCHEME {
                sm2: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::ECSchnorr(hash_alg) => TPMU_ASYM_SCHEME {
                ecschnorr: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::RSAES => TPMU_ASYM_SCHEME {
                rsaes: Default::default(),
            },
            AsymSchemeUnion::RSAOAEP(hash_alg) => TPMU_ASYM_SCHEME {
                oaep: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
            AsymSchemeUnion::AnySig(hash_alg) => TPMU_ASYM_SCHEME {
                anySig: TPMS_SCHEME_HASH { hashAlg: hash_alg },
            },
        };

        TPMT_RSA_SCHEME { scheme, details }
    }
}

/// Rust native representation of an asymmetric signature.
///
/// The structure contains the signature as a byte vector and the scheme with which the signature
/// was created.
#[derive(Debug)]
pub struct Signature {
    pub scheme: AsymSchemeUnion,
    pub signature: Vec<u8>,
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
                let scheme = AsymSchemeUnion::RSASSA(hash_alg);
                let signature_buf = tss_signature.signature.rsassa.sig;
                let mut signature = signature_buf.buffer.to_vec();
                let buf_size = signature_buf.size.into();
                if buf_size > signature.len() {
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
                signature.truncate(buf_size);

                Ok(Signature { scheme, signature })
            }
            TPM2_ALG_ECDH => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_ECDSA => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_OAEP => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_RSAPSS => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_RSAES => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_ECMQV => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_SM2 => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_ECSCHNORR => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            TPM2_ALG_ECDAA => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

impl TryFrom<Signature> for TPMT_SIGNATURE {
    type Error = Error;
    fn try_from(sig: Signature) -> Result<Self> {
        let len = sig.signature.len();
        if len > 512 {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }

        let mut buffer = [0_u8; 512];
        buffer[..len].clone_from_slice(&sig.signature[..len]);

        match sig.scheme {
            AsymSchemeUnion::ECDH(_) => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            AsymSchemeUnion::ECMQV(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::RSASSA(hash_alg) => Ok(TPMT_SIGNATURE {
                sigAlg: TPM2_ALG_RSASSA,
                signature: TPMU_SIGNATURE {
                    rsassa: TPMS_SIGNATURE_RSA {
                        hash: hash_alg,
                        sig: TPM2B_PUBLIC_KEY_RSA {
                            size: len.try_into().expect("Failed to convert length to u16"), // Should never panic as per the check above
                            buffer,
                        },
                    },
                },
            }),
            AsymSchemeUnion::RSAPSS(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::ECDSA(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::ECDAA(_, _) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::SM2(_) => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            AsymSchemeUnion::ECSchnorr(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::RSAES => Err(Error::local_error(WrapperErrorKind::UnsupportedParam)),
            AsymSchemeUnion::RSAOAEP(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
            AsymSchemeUnion::AnySig(_) => {
                Err(Error::local_error(WrapperErrorKind::UnsupportedParam))
            }
        }
    }
}

/// Rust native wrapper for session attributes objects.
#[derive(Copy, Clone, Debug, Default)]
pub struct TpmaSession(TPMA_SESSION);

impl TpmaSession {
    /// Create a new session attributes object.
    pub fn new() -> TpmaSession {
        TpmaSession(0)
    }

    /// Set flag.
    pub fn with_flag(mut self, flag: TPMA_SESSION) -> Self {
        self.0 |= flag;
        self
    }

    /// Get mask for all set flags.
    pub fn mask(self) -> TPMA_SESSION {
        self.0
    }

    /// Get all set flags.
    pub fn flags(self) -> TPMA_SESSION {
        self.0
    }
}

/// Rust native wrapper for `TPMS_CONTEXT` objects.
///
/// This structure is intended to help with persisting object contexts. As the main reason for
/// saving the context of an object is to be able to re-use it later, on demand, a serializable
/// structure is most commonly needed. `TpmsContext` implements the `Serialize` and `Deserialize`
/// defined by `serde`.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
                .or_else(|_| Err(Error::local_error(WrapperErrorKind::WrongParamSize)))?,
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
        for (i, val) in context.context_blob.into_iter().enumerate() {
            buffer[i] = val;
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

/// Convenience method for generating `TPM2B_PUBLIC` objects for RSA keys based on the provided
/// parameters.
///
/// The method defaults the following values:
/// * asymmetric scheme used - RSA SSA with SHA-256 as the hash algorithm
/// * symmetric algorithm associated with the object - 256 bit AES in CFB mode
/// * name algorithm - SHA-256
/// * object attributes - fixed TPM, fixed parent, sensitive data origin and user with auth are set
pub fn get_rsa_public(restricted: bool, decrypt: bool, sign: bool, key_bits: u16) -> TPM2B_PUBLIC {
    let symmetric = TpmtSymDefBuilder::aes_256_cfb_object();
    let scheme = AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256);
    let rsa_parms = TpmsRsaParmsBuilder::new()
        .with_symmetric(symmetric)
        .with_key_bits(key_bits)
        .with_scheme(scheme)
        .build()
        .unwrap(); // should not fail as we control the params
    let mut object_attributes = ObjectAttributes(0);
    object_attributes.set_fixed_tpm(true);
    object_attributes.set_fixed_parent(true);
    object_attributes.set_sensitive_data_origin(true);
    object_attributes.set_user_with_auth(true);
    object_attributes.set_decrypt(decrypt);
    object_attributes.set_sign_encrypt(sign);
    object_attributes.set_restricted(restricted);

    Tpm2BPublicBuilder::new()
        .with_type(TPM2_ALG_RSA)
        .with_name_alg(TPM2_ALG_SHA256)
        .with_object_attributes(object_attributes)
        .with_parms(PublicParmsUnion::RsaDetail(rsa_parms))
        .build()
        .unwrap() // should not fail as we control the params
}

/// Enum describing the object hierarchies in a TPM 2.0.
#[derive(Debug, Clone, Copy)]
pub enum Hierarchy {
    Null,
    Owner,
    Platform,
    Endorsement,
}

impl Hierarchy {
    /// Get the ESYS resource handle for the hierarchy.
    pub fn esys_rh(self) -> TPMI_RH_HIERARCHY {
        match self {
            Hierarchy::Null => ESYS_TR_RH_NULL,
            Hierarchy::Owner => ESYS_TR_RH_OWNER,
            Hierarchy::Platform => ESYS_TR_RH_PLATFORM,
            Hierarchy::Endorsement => ESYS_TR_RH_ENDORSEMENT,
        }
    }

    /// Get the TPM resource handle for the hierarchy.
    pub fn rh(self) -> TPM2_RH {
        match self {
            Hierarchy::Null => TPM2_RH_NULL,
            Hierarchy::Owner => TPM2_RH_OWNER,
            Hierarchy::Platform => TPM2_RH_PLATFORM,
            Hierarchy::Endorsement => TPM2_RH_ENDORSEMENT,
        }
    }
}

impl TryFrom<TPM2_HANDLE> for Hierarchy {
    type Error = Error;

    fn try_from(handle: TPM2_HANDLE) -> Result<Self> {
        match handle {
            TPM2_RH_NULL | ESYS_TR_RH_NULL => Ok(Hierarchy::Null),
            TPM2_RH_OWNER | ESYS_TR_RH_OWNER => Ok(Hierarchy::Owner),
            TPM2_RH_PLATFORM | ESYS_TR_RH_PLATFORM => Ok(Hierarchy::Platform),
            TPM2_RH_ENDORSEMENT | ESYS_TR_RH_ENDORSEMENT => Ok(Hierarchy::Endorsement),
            _ => Err(Error::local_error(WrapperErrorKind::InconsistentParams)),
        }
    }
}

/// Rust native wrapper for `TPMT_TK_VERIFIED` objects.
#[derive(Debug)]
pub struct TpmtTkVerified {
    hierarchy: Hierarchy,
    digest: Vec<u8>,
}

impl TpmtTkVerified {
    /// Get the hierarchy associated with the verification ticket.
    pub fn hierarchy(&self) -> Hierarchy {
        self.hierarchy
    }

    /// Get the digest associated with the verification ticket.
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

impl TryFrom<TPMT_TK_VERIFIED> for TpmtTkVerified {
    type Error = Error;

    fn try_from(tss_verif: TPMT_TK_VERIFIED) -> Result<Self> {
        if tss_verif.tag != TPM2_ST_VERIFIED {
            return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
        }

        let len = tss_verif.digest.size.into();
        let mut digest = tss_verif.digest.buffer.to_vec();
        digest.truncate(len);

        let hierarchy = tss_verif.hierarchy.try_into()?;

        Ok(TpmtTkVerified { hierarchy, digest })
    }
}

impl TryFrom<TpmtTkVerified> for TPMT_TK_VERIFIED {
    type Error = Error;

    fn try_from(verif: TpmtTkVerified) -> Result<Self> {
        let digest = verif.digest;
        if digest.len() > 64 {
            return Err(Error::local_error(WrapperErrorKind::WrongParamSize));
        }

        let mut buffer = [0; 64];
        buffer[..digest.len()].clone_from_slice(&digest[..digest.len()]);

        Ok(TPMT_TK_VERIFIED {
            tag: TPM2_ST_VERIFIED,
            hierarchy: verif.hierarchy.rh(),
            digest: TPM2B_DIGEST {
                size: digest.len().try_into().unwrap(), // should not fail based on the checks done above
                buffer,
            },
        })
    }
}
