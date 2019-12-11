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

use crate::constants::*;
use crate::response_code::{Result, Tss2ResponseCode};
use crate::tss2_esys::*;
use bitfield::bitfield;
use serde::{Deserialize, Serialize};
use std::convert::{TryFrom, TryInto};

pub struct Tpm2BPublicBuilder {
    type_: Option<TPMI_ALG_PUBLIC>,
    name_alg: TPMI_ALG_HASH,
    object_attributes: ObjectAttributes,
    auth_policy: TPM2B_DIGEST,
    parameters: Option<PublicParmsUnion>,
    unique: Option<PublicIdUnion>,
}

impl Tpm2BPublicBuilder {
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

    pub fn with_type(mut self, type_: TPMI_ALG_PUBLIC) -> Self {
        self.type_ = Some(type_);
        self
    }

    pub fn with_name_alg(mut self, name_alg: TPMI_ALG_HASH) -> Self {
        self.name_alg = name_alg;
        self
    }

    pub fn with_object_attributes(mut self, obj_attr: ObjectAttributes) -> Self {
        self.object_attributes = obj_attr;
        self
    }

    pub fn with_auth_policy(mut self, size: u16, buffer: [u8; 64]) -> Self {
        self.auth_policy = TPM2B_DIGEST { size, buffer };
        self
    }

    pub fn with_parms(mut self, parameters: PublicParmsUnion) -> Self {
        self.parameters = Some(parameters);
        self
    }

    pub fn with_unique(mut self, unique: PublicIdUnion) -> Self {
        self.unique = Some(unique);
        self
    }

    pub fn build(mut self) -> TPM2B_PUBLIC {
        match self.type_ {
            Some(TPM2_ALG_RSA) => {
                // RSA key
                let mut parameters;
                let unique;
                if let Some(PublicParmsUnion::RsaDetail(parms)) = self.parameters {
                    parameters = TPMU_PUBLIC_PARMS { rsaDetail: parms };
                } else if self.parameters.is_none() {
                    panic!("No key parameters provided");
                } else {
                    panic!("Wrong parameter type provided");
                }

                if let Some(PublicIdUnion::Rsa(rsa_unique)) = self.unique {
                    unique = TPMU_PUBLIC_ID { rsa: *rsa_unique };
                } else if self.unique.is_none() {
                    unique = Default::default();
                } else {
                    panic!("Wrong unique type provided");
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

                TPM2B_PUBLIC {
                    size: std::mem::size_of::<TPMT_PUBLIC>()
                        .try_into()
                        .expect("Failed to convert usize to u16"),
                    publicArea: TPMT_PUBLIC {
                        type_: self.type_.expect("Object type not provided"),
                        nameAlg: self.name_alg,
                        objectAttributes: self.object_attributes.0,
                        authPolicy: self.auth_policy,
                        parameters,
                        unique,
                    },
                }
            }
            _ => unimplemented!(),
        }
    }
}

impl Default for Tpm2BPublicBuilder {
    fn default() -> Self {
        Tpm2BPublicBuilder::new()
    }
}

#[derive(Default)]
pub struct TpmsRsaParmsBuilder {
    symmetric: TPMT_SYM_DEF_OBJECT,
    scheme: Option<AsymSchemeUnion>,
    key_bits: TPMI_RSA_KEY_BITS,
    exponent: u32,
}

impl TpmsRsaParmsBuilder {
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

    pub fn with_symmetric(mut self, symmetric: TPMT_SYM_DEF_OBJECT) -> Self {
        self.symmetric = symmetric;
        self
    }

    pub fn with_scheme(mut self, scheme: AsymSchemeUnion) -> Self {
        self.scheme = Some(scheme);
        self
    }

    pub fn with_key_bits(mut self, key_bits: TPMI_RSA_KEY_BITS) -> Self {
        self.key_bits = key_bits;
        self
    }

    pub fn with_exponent(mut self, exponent: u32) -> Self {
        self.exponent = exponent;
        self
    }

    pub fn build(self) -> TPMS_RSA_PARMS {
        TPMS_RSA_PARMS {
            symmetric: self.symmetric,
            scheme: self
                .scheme
                .expect("Scheme was not provided")
                .get_rsa_scheme(),
            keyBits: self.key_bits,
            exponent: self.exponent,
        }
    }
}

pub struct TpmtSymDefBuilder {
    algorithm: Option<TPM2_ALG_ID>,
    key_bits: u16,
    mode: TPM2_ALG_ID,
}

impl TpmtSymDefBuilder {
    pub fn new() -> Self {
        TpmtSymDefBuilder {
            algorithm: None,
            key_bits: 0,
            mode: TPM2_ALG_NULL,
        }
    }

    pub fn with_algorithm(mut self, algorithm: TPM2_ALG_ID) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    pub fn with_key_bits(mut self, key_bits: TPM2_KEY_BITS) -> Self {
        self.key_bits = key_bits;
        self
    }

    pub fn with_hash(mut self, hash: TPM2_ALG_ID) -> Self {
        self.key_bits = hash;
        self
    }

    pub fn with_mode(mut self, mode: TPM2_ALG_ID) -> Self {
        self.mode = mode;
        self
    }

    pub fn build_object(self) -> TPMT_SYM_DEF_OBJECT {
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
            _ => unimplemented!(),
        }

        TPMT_SYM_DEF_OBJECT {
            algorithm: self.algorithm.expect("No algorithm provided"),
            keyBits: key_bits,
            mode,
        }
    }

    pub fn aes_256_cfb() -> TPMT_SYM_DEF {
        TPMT_SYM_DEF {
            algorithm: TPM2_ALG_AES,
            keyBits: TPMU_SYM_KEY_BITS { aes: 256 },
            mode: TPMU_SYM_MODE { aes: TPM2_ALG_CFB },
        }
    }

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

pub enum PublicIdUnion {
    KeyedHash(TPM2B_DIGEST),
    Sym(TPM2B_DIGEST),
    Rsa(Box<TPM2B_PUBLIC_KEY_RSA>),
    Ecc(Box<TPMS_ECC_POINT>),
}

impl PublicIdUnion {
    pub fn from_public(public: &TPM2B_PUBLIC) -> Self {
        match public.publicArea.type_ {
            TPM2_ALG_RSA => {
                // TODO Issue #2: Should this method be unsafe?
                PublicIdUnion::Rsa(Box::from(unsafe { public.publicArea.unique.rsa }))
            }
            TPM2_ALG_ECC => unimplemented!(),
            TPM2_ALG_SYMCIPHER => unimplemented!(),
            TPM2_ALG_KEYEDHASH => unimplemented!(),
            _ => unimplemented!(),
        }
    }
}

pub enum PublicParmsUnion {
    KeyedHashDetail(TPMS_KEYEDHASH_PARMS),
    SymDetail(TPMS_SYMCIPHER_PARMS),
    RsaDetail(TPMS_RSA_PARMS),
    EccDetail(TPMS_ECC_PARMS),
    AsymDetail(TPMS_ASYM_PARMS),
}

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
    pub fn scheme_id(&self) -> TPM2_ALG_ID {
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

pub struct Signature {
    pub scheme: AsymSchemeUnion,
    pub signature: Vec<u8>,
}

impl TryFrom<TPMT_SIGNATURE> for Signature {
    type Error = Tss2ResponseCode;

    fn try_from(tss_signature: TPMT_SIGNATURE) -> Result<Self> {
        match tss_signature.sigAlg {
            TPM2_ALG_RSASSA => {
                let hash_alg = unsafe { tss_signature.signature.rsassa.hash };
                let scheme = AsymSchemeUnion::RSASSA(hash_alg);
                let signature_buf = unsafe { tss_signature.signature.rsassa.sig };
                let mut signature = signature_buf.buffer.to_vec();
                signature.truncate(signature_buf.size.into());

                Ok(Signature { scheme, signature })
            }
            TPM2_ALG_ECDH => unimplemented!(),
            TPM2_ALG_ECDSA => unimplemented!(),
            TPM2_ALG_OAEP => unimplemented!(),
            TPM2_ALG_RSAPSS => unimplemented!(),
            TPM2_ALG_RSAES => unimplemented!(),
            TPM2_ALG_ECMQV => unimplemented!(),
            TPM2_ALG_SM2 => unimplemented!(),
            TPM2_ALG_ECSCHNORR => unimplemented!(),
            TPM2_ALG_ECDAA => unimplemented!(),
            _ => Err(Tss2ResponseCode::new(TPM2_RC_SCHEME)),
        }
    }
}

impl TryFrom<Signature> for TPMT_SIGNATURE {
    type Error = Tss2ResponseCode;
    fn try_from(sig: Signature) -> Result<Self> {
        let len = sig.signature.len();
        let mut buffer = [0u8; 512];
        for (idx, byte) in sig.signature.into_iter().enumerate() {
            buffer[idx] = byte;
        }
        match sig.scheme {
            AsymSchemeUnion::ECDH(_) => unimplemented!(),
            AsymSchemeUnion::ECMQV(_) => unimplemented!(),
            AsymSchemeUnion::RSASSA(hash_alg) => Ok(TPMT_SIGNATURE {
                sigAlg: TPM2_ALG_RSASSA,
                signature: TPMU_SIGNATURE {
                    rsassa: TPMS_SIGNATURE_RSA {
                        hash: hash_alg,
                        sig: TPM2B_PUBLIC_KEY_RSA {
                            size: len
                                .try_into()
                                .map_err(|_| Tss2ResponseCode::new(TPM2_RC_SIZE))?,
                            buffer,
                        },
                    },
                },
            }),
            AsymSchemeUnion::RSAPSS(_) => unimplemented!(),
            AsymSchemeUnion::ECDSA(_) => unimplemented!(),
            AsymSchemeUnion::ECDAA(_, _) => unimplemented!(),
            AsymSchemeUnion::SM2(_) => unimplemented!(),
            AsymSchemeUnion::ECSchnorr(_) => unimplemented!(),
            AsymSchemeUnion::RSAES => unimplemented!(),
            AsymSchemeUnion::RSAOAEP(_) => unimplemented!(),
            AsymSchemeUnion::AnySig(_) => unimplemented!(),
        }
    }
}

#[derive(Default)]
pub struct TpmaSession(TPMA_SESSION);

impl TpmaSession {
    pub fn new() -> TpmaSession {
        TpmaSession(0)
    }

    pub fn with_flag(mut self, flag: TPMA_SESSION) -> Self {
        self.0 |= flag;
        self
    }

    pub fn mask(&self) -> TPMA_SESSION {
        self.0
    }

    pub fn flags(&self) -> TPMA_SESSION {
        self.0
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TpmsContext {
    sequence: u64,
    saved_handle: TPMI_DH_CONTEXT,
    hierarchy: TPMI_RH_HIERARCHY,
    context_blob: Vec<u8>,
}

impl From<TPMS_CONTEXT> for TpmsContext {
    fn from(tss2_context: TPMS_CONTEXT) -> Self {
        let mut context = TpmsContext {
            sequence: tss2_context.sequence,
            saved_handle: tss2_context.savedHandle,
            hierarchy: tss2_context.hierarchy,
            context_blob: tss2_context.contextBlob.buffer.to_vec(),
        };
        context
            .context_blob
            .truncate(tss2_context.contextBlob.size.try_into().unwrap());
        context
    }
}

impl TryFrom<TpmsContext> for TPMS_CONTEXT {
    type Error = Tss2ResponseCode;

    fn try_from(context: TpmsContext) -> Result<Self> {
        let buffer_size = context.context_blob.len();
        if buffer_size > 5188 {
            return Err(Tss2ResponseCode::new(TPM2_RC_SIZE));
        }
        let mut buffer = [0u8; 5188];
        for (i, val) in context.context_blob.into_iter().enumerate() {
            buffer[i] = val;
        }
        Ok(TPMS_CONTEXT {
            sequence: context.sequence,
            savedHandle: context.saved_handle,
            hierarchy: context.hierarchy,
            contextBlob: TPM2B_CONTEXT_DATA {
                size: buffer_size.try_into().unwrap(),
                buffer,
            },
        })
    }
}

pub fn get_rsa_public(restricted: bool, decrypt: bool, sign: bool, key_bits: u16) -> TPM2B_PUBLIC {
    let symmetric = TpmtSymDefBuilder::aes_256_cfb_object();
    let scheme = AsymSchemeUnion::RSASSA(TPM2_ALG_SHA256);
    let rsa_parms = TpmsRsaParmsBuilder::new()
        .with_symmetric(symmetric)
        .with_key_bits(key_bits)
        .with_scheme(scheme)
        .build();
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
}
