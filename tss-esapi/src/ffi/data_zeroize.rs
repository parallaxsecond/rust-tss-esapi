// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    interface_types::algorithm::{
        EccSchemeAlgorithm, KeyDerivationFunction, KeyedHashSchemeAlgorithm, PublicAlgorithm,
        RsaSchemeAlgorithm, SymmetricObject,
    },
    tss2_esys::{
        TPM2B_CREATION_DATA, TPM2B_DATA, TPM2B_DIGEST, TPM2B_ECC_PARAMETER, TPM2B_ENCRYPTED_SECRET,
        TPM2B_ID_OBJECT, TPM2B_IV, TPM2B_MAX_BUFFER, TPM2B_MAX_NV_BUFFER, TPM2B_NAME,
        TPM2B_PRIVATE, TPM2B_PRIVATE_KEY_RSA, TPM2B_PRIVATE_VENDOR_SPECIFIC, TPM2B_PUBLIC,
        TPM2B_PUBLIC_KEY_RSA, TPM2B_SENSITIVE_CREATE, TPM2B_SENSITIVE_DATA, TPM2B_SYM_KEY,
        TPML_PCR_SELECTION, TPMS_CREATION_DATA, TPMS_ECC_PARMS, TPMS_ECC_POINT,
        TPMS_KEYEDHASH_PARMS, TPMS_PCR_SELECTION, TPMS_RSA_PARMS, TPMS_SCHEME_ECDAA,
        TPMS_SCHEME_HASH, TPMS_SCHEME_XOR, TPMS_SENSITIVE_CREATE, TPMS_SYMCIPHER_PARMS,
        TPMT_ECC_SCHEME, TPMT_KDF_SCHEME, TPMT_KEYEDHASH_SCHEME, TPMT_PUBLIC, TPMT_RSA_SCHEME,
        TPMT_SYM_DEF_OBJECT, TPMT_TK_AUTH, TPMT_TK_CREATION, TPMT_TK_HASHCHECK, TPMT_TK_VERIFIED,
    },
};
use std::convert::TryFrom;
use zeroize::Zeroize;
// /////////////////////////////////////////////////////////////////////////
// This module provides a the internal FfiDataZeroize trait
// and implementations of this trait for several of the
// generated TPM types that is used in TSS. In order to be
// able to zeroize sensitive information that may be stored
// in these types when using them in calls to the TSS APIs.
// To zeroize sensitive data when no longer needed is considered
// good cryptographic hygiene and reduces the chances of sensitive data
// being leaked.
//
// This has been implemented as trait in order to have a consistent way
// to use the zeroize functionality on the TSS FFI types and to be able
// to use it in generic functions that deal with taking ownership of data
// that has been allocated by TSS in order to zeroize the source memory.
// /////////////////////////////////////////////////////////////////////////

/// A trait for zeroizing FFI data.
pub(crate) trait FfiDataZeroize {
    fn ffi_data_zeroize(&mut self);
}

macro_rules! implement_ffi_data_zeroizer_trait_for_named_fields_type {
    ($tss_type:ident, $($field_name:ident), *) => {
        impl FfiDataZeroize for $tss_type {
            fn ffi_data_zeroize(&mut self) {
                $(
                    self.$field_name.zeroize();
                )*
            }
        }
    };
}

macro_rules! implement_ffi_data_zeroizer_trait_for_structured_named_fields_type {
    ($tss_type:ident, $($field_name:ident), *) => {
        impl FfiDataZeroize for $tss_type {
            fn ffi_data_zeroize(&mut self) {
                $(
                    self.$field_name.ffi_data_zeroize();
                )*
            }
        }
    };
}

macro_rules! implement_ffi_data_zeroizer_trait_for_named_field_buffer_type {
    ($tss_type:ident,$buffer_field_name:ident) => {
        implement_ffi_data_zeroizer_trait_for_named_fields_type!(
            $tss_type,
            size,
            $buffer_field_name
        );
    };
}

macro_rules! implement_ffi_data_zeroizer_trait_for_named_field_structured_buffer_type {
    ($tss_type:ident,$buffer_field_name:ident) => {
        impl FfiDataZeroize for $tss_type {
            fn ffi_data_zeroize(&mut self) {
                self.size.zeroize();
                self.$buffer_field_name.ffi_data_zeroize();
            }
        }
    };
}

macro_rules! implement_ffi_data_zeroizer_trait_for_buffer_type {
    ($tss_type:ident) => {
        implement_ffi_data_zeroizer_trait_for_named_field_buffer_type!($tss_type, buffer);
    };
}

macro_rules! implement_ffi_data_zeroizer_trait_for_ticket_type {
    ($tss_type:ident) => {
        impl FfiDataZeroize for $tss_type {
            fn ffi_data_zeroize(&mut self) {
                self.tag.zeroize();
                self.hierarchy.zeroize();
                self.digest.ffi_data_zeroize();
            }
        }
    };
}

// ////////////////////////////////////////////////////////////////////////////////////
// Implementation of FfiDataZeroize for TPM2B types
// ////////////////////////////////////////////////////////////////////////////////////
// TPM2B_AUTH, TPM2B_NONCE, TPM2B_TIMEOUT == TPM2B_DIGEST
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_DIGEST);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_DATA);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_ECC_PARAMETER);
implement_ffi_data_zeroizer_trait_for_named_field_buffer_type!(TPM2B_ENCRYPTED_SECRET, secret);
implement_ffi_data_zeroizer_trait_for_named_field_buffer_type!(TPM2B_ID_OBJECT, credential);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_IV);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_MAX_BUFFER);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_MAX_NV_BUFFER);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_PRIVATE);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_PRIVATE_KEY_RSA);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_PRIVATE_VENDOR_SPECIFIC);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_PUBLIC_KEY_RSA);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_SENSITIVE_DATA);
implement_ffi_data_zeroizer_trait_for_buffer_type!(TPM2B_SYM_KEY);
implement_ffi_data_zeroizer_trait_for_named_field_structured_buffer_type!(
    TPM2B_CREATION_DATA,
    creationData
);
implement_ffi_data_zeroizer_trait_for_named_field_structured_buffer_type!(
    TPM2B_SENSITIVE_CREATE,
    sensitive
);
implement_ffi_data_zeroizer_trait_for_named_field_buffer_type!(TPM2B_NAME, name);
implement_ffi_data_zeroizer_trait_for_named_field_structured_buffer_type!(TPM2B_PUBLIC, publicArea);
// ////////////////////////////////////////////////////////////////////////////////////
// Implement FFiDataZeroize for TPMS types
// ////////////////////////////////////////////////////////////////////////////////////
implement_ffi_data_zeroizer_trait_for_structured_named_fields_type!(
    TPMS_SENSITIVE_CREATE,
    userAuth,
    data
);

impl FfiDataZeroize for TPMS_CREATION_DATA {
    fn ffi_data_zeroize(&mut self) {
        self.pcrSelect.ffi_data_zeroize();
        self.pcrDigest.ffi_data_zeroize();
        self.locality.zeroize();
        self.parentNameAlg.zeroize();
        self.parentName.ffi_data_zeroize();
        self.parentQualifiedName.ffi_data_zeroize();
        self.outsideInfo.ffi_data_zeroize();
    }
}

implement_ffi_data_zeroizer_trait_for_named_fields_type!(
    TPMS_PCR_SELECTION,
    hash,
    sizeofSelect,
    pcrSelect
);

// TPMS_SCHEME_HMAC == TPMS_SCHEME_HASH
implement_ffi_data_zeroizer_trait_for_named_fields_type!(TPMS_SCHEME_HASH, hashAlg);
implement_ffi_data_zeroizer_trait_for_named_fields_type!(TPMS_SCHEME_XOR, hashAlg, kdf);
implement_ffi_data_zeroizer_trait_for_named_fields_type!(TPMS_SCHEME_ECDAA, hashAlg, count);

implement_ffi_data_zeroizer_trait_for_structured_named_fields_type!(TPMS_KEYEDHASH_PARMS, scheme);
implement_ffi_data_zeroizer_trait_for_structured_named_fields_type!(TPMS_SYMCIPHER_PARMS, sym);

impl FfiDataZeroize for TPMS_ECC_PARMS {
    fn ffi_data_zeroize(&mut self) {
        self.symmetric.ffi_data_zeroize();
        self.scheme.ffi_data_zeroize();
        self.curveID.zeroize();
        self.kdf.ffi_data_zeroize();
    }
}

impl FfiDataZeroize for TPMS_RSA_PARMS {
    fn ffi_data_zeroize(&mut self) {
        self.symmetric.ffi_data_zeroize();
        self.scheme.ffi_data_zeroize();
        self.keyBits.zeroize();
        self.exponent.zeroize();
    }
}

implement_ffi_data_zeroizer_trait_for_structured_named_fields_type!(TPMS_ECC_POINT, x, y);
// ////////////////////////////////////////////////////////////////////////////////////
// Implement FFiDataZeroize for TPML types
// ////////////////////////////////////////////////////////////////////////////////////
impl FfiDataZeroize for TPML_PCR_SELECTION {
    fn ffi_data_zeroize(&mut self) {
        self.count.zeroize();
        self.pcrSelections
            .iter_mut()
            .for_each(|v| v.ffi_data_zeroize());
    }
}
// ////////////////////////////////////////////////////////////////////////////////////
// Implement FFiDataZeroize for TPMT types
// ////////////////////////////////////////////////////////////////////////////////////
impl FfiDataZeroize for TPMT_SYM_DEF_OBJECT {
    fn ffi_data_zeroize(&mut self) {
        if let Ok(algorithm) = SymmetricObject::try_from(self.algorithm) {
            match algorithm {
                SymmetricObject::Aes => {
                    unsafe {
                        self.keyBits.aes.zeroize();
                    }
                    unsafe {
                        self.mode.aes.zeroize();
                    }
                }
                SymmetricObject::Sm4 => {
                    unsafe {
                        self.keyBits.sm4.zeroize();
                    }
                    unsafe {
                        self.mode.sm4.zeroize();
                    }
                }
                SymmetricObject::Camellia => {
                    unsafe {
                        self.keyBits.camellia.zeroize();
                    }
                    unsafe {
                        self.mode.camellia.zeroize();
                    }
                }
                SymmetricObject::Null | SymmetricObject::Tdes => {}
            }
        }
        self.algorithm.zeroize();
    }
}

impl FfiDataZeroize for TPMT_PUBLIC {
    fn ffi_data_zeroize(&mut self) {
        //
        if let Ok(public_algorithm) = PublicAlgorithm::try_from(self.type_) {
            match public_algorithm {
                PublicAlgorithm::Rsa => {
                    self.objectAttributes.zeroize();
                    self.nameAlg.zeroize();
                    self.authPolicy.ffi_data_zeroize();
                    unsafe {
                        self.parameters.rsaDetail.ffi_data_zeroize();
                    }
                    unsafe {
                        self.unique.rsa.ffi_data_zeroize();
                    }
                }
                PublicAlgorithm::KeyedHash => {
                    self.objectAttributes.zeroize();
                    self.nameAlg.zeroize();
                    self.authPolicy.ffi_data_zeroize();
                    unsafe {
                        self.parameters.keyedHashDetail.ffi_data_zeroize();
                    }
                    unsafe {
                        self.unique.keyedHash.ffi_data_zeroize();
                    }
                }
                PublicAlgorithm::Ecc => {
                    self.objectAttributes.zeroize();
                    self.nameAlg.zeroize();
                    self.authPolicy.ffi_data_zeroize();
                    unsafe {
                        self.parameters.eccDetail.ffi_data_zeroize();
                    }
                    unsafe {
                        self.unique.ecc.ffi_data_zeroize();
                    }
                }
                PublicAlgorithm::SymCipher => {
                    self.objectAttributes.zeroize();
                    self.nameAlg.zeroize();
                    self.authPolicy.ffi_data_zeroize();
                    unsafe {
                        self.parameters.symDetail.ffi_data_zeroize();
                    }
                    unsafe {
                        self.unique.sym.ffi_data_zeroize();
                    }
                }
            }
            self.type_.zeroize();
        }
    }
}

impl FfiDataZeroize for TPMT_KEYEDHASH_SCHEME {
    fn ffi_data_zeroize(&mut self) {
        if let Ok(keyed_hash_scheme_algorithm) = KeyedHashSchemeAlgorithm::try_from(self.scheme) {
            match keyed_hash_scheme_algorithm {
                KeyedHashSchemeAlgorithm::Xor => unsafe {
                    self.details.exclusiveOr.ffi_data_zeroize();
                },
                KeyedHashSchemeAlgorithm::Hmac => unsafe {
                    self.details.hmac.ffi_data_zeroize();
                },
                KeyedHashSchemeAlgorithm::Null => {}
            }
        }
        self.scheme.zeroize();
    }
}

impl FfiDataZeroize for TPMT_RSA_SCHEME {
    fn ffi_data_zeroize(&mut self) {
        if let Ok(rsa_scheme_algorithm) = RsaSchemeAlgorithm::try_from(self.scheme) {
            match rsa_scheme_algorithm {
                RsaSchemeAlgorithm::RsaSsa => unsafe {
                    self.details.rsassa.ffi_data_zeroize();
                },
                RsaSchemeAlgorithm::RsaEs => {}
                RsaSchemeAlgorithm::RsaPss => unsafe {
                    self.details.rsapss.ffi_data_zeroize();
                },
                RsaSchemeAlgorithm::Oaep => unsafe {
                    self.details.oaep.ffi_data_zeroize();
                },
                RsaSchemeAlgorithm::Null => {}
            }
        }
        self.scheme.zeroize();
    }
}

impl FfiDataZeroize for TPMT_ECC_SCHEME {
    fn ffi_data_zeroize(&mut self) {
        if let Ok(ecc_scheme_algorithm) = EccSchemeAlgorithm::try_from(self.scheme) {
            match ecc_scheme_algorithm {
                EccSchemeAlgorithm::EcDsa => unsafe {
                    self.details.ecdsa.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::EcDh => unsafe {
                    self.details.ecdh.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::EcDaa => unsafe {
                    self.details.ecdaa.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::Sm2 => unsafe {
                    self.details.sm2.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::EcSchnorr => unsafe {
                    self.details.ecschnorr.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::EcMqv => unsafe {
                    self.details.ecmqv.ffi_data_zeroize();
                },
                EccSchemeAlgorithm::Null => {}
            }
        }
        self.scheme.zeroize();
    }
}

impl FfiDataZeroize for TPMT_KDF_SCHEME {
    fn ffi_data_zeroize(&mut self) {
        if let Ok(key_derivation_function) = KeyDerivationFunction::try_from(self.scheme) {
            match key_derivation_function {
                KeyDerivationFunction::Kdf1Sp800_56a => unsafe {
                    self.details.kdf1_sp800_56a.ffi_data_zeroize();
                },
                KeyDerivationFunction::Kdf2 => unsafe {
                    self.details.kdf2.ffi_data_zeroize();
                },
                KeyDerivationFunction::Kdf1Sp800_108 => unsafe {
                    self.details.kdf1_sp800_108.ffi_data_zeroize();
                },
                KeyDerivationFunction::Mgf1 => unsafe {
                    self.details.mgf1.ffi_data_zeroize();
                },
                KeyDerivationFunction::Null => {}
            }
        }
        self.scheme.zeroize();
    }
}
// Tickets
implement_ffi_data_zeroizer_trait_for_ticket_type!(TPMT_TK_CREATION);
implement_ffi_data_zeroizer_trait_for_ticket_type!(TPMT_TK_VERIFIED);
implement_ffi_data_zeroizer_trait_for_ticket_type!(TPMT_TK_AUTH);
implement_ffi_data_zeroizer_trait_for_ticket_type!(TPMT_TK_HASHCHECK);

// /////////////////////////////////////////////////////////////////////////
// UNIT TESTS FOR FFI DATA ZEROIZE
//
// These unit tests needs to be here because the trait is internal to the crate
// and can there for not be tested using integration tests.
// /////////////////////////////////////////////////////////////////////////
macro_rules! implement_zeroize_test_for_named_field_structured_buffer_type {
    ($tss_type:ident, $buffer_field_name:ident, $fn_name:ident) => {
        #[test]
        fn $fn_name() {
            const fn fill_with_ones<const SIZE: usize>() -> [u8; SIZE] {
                [1u8; SIZE]
            }

            let expected: $tss_type = unsafe { std::mem::zeroed() };
            let mut actual = $tss_type {
                size: 10,
                $buffer_field_name: fill_with_ones(),
            };
            actual.ffi_data_zeroize();
            assert_eq!(expected.size, actual.size);
            assert_eq!(expected.$buffer_field_name, actual.$buffer_field_name);
        }
    };
}

macro_rules! implement_zeroize_test_buffer_type {
    ($tss_type:ident, $fn_name:ident) => {
        implement_zeroize_test_for_named_field_structured_buffer_type!($tss_type, buffer, $fn_name);
    };
}

implement_zeroize_test_buffer_type!(TPM2B_DIGEST, test_tpm2b_digest_ffi_data_zeroize);
implement_zeroize_test_buffer_type!(TPM2B_DATA, test_tpm2b_data_ffi_data_zeroize);
implement_zeroize_test_buffer_type!(TPM2B_ECC_PARAMETER, test_tpm2b_parameter_ffi_data_zeroize);
implement_zeroize_test_for_named_field_structured_buffer_type!(
    TPM2B_ENCRYPTED_SECRET,
    secret,
    test_tpm2b_encrypted_secret_ffi_data_zeroize
);
implement_zeroize_test_for_named_field_structured_buffer_type!(
    TPM2B_ID_OBJECT,
    credential,
    test_tpm2b_id_object_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(TPM2B_IV, test_tpm2b_iv_ffi_data_zeroize);
implement_zeroize_test_buffer_type!(TPM2B_MAX_BUFFER, test_tpm2b_max_buffer_ffi_data_zeroize);
implement_zeroize_test_buffer_type!(
    TPM2B_MAX_NV_BUFFER,
    test_tpm2b_max_nv_buffer_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(TPM2B_PRIVATE, test_tpm2b_private_ffi_data_zeroize);
implement_zeroize_test_buffer_type!(
    TPM2B_PRIVATE_KEY_RSA,
    test_tpm2b_private_key_rsa_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(
    TPM2B_PRIVATE_VENDOR_SPECIFIC,
    test_tpm2b_private_vendor_specific_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(
    TPM2B_PUBLIC_KEY_RSA,
    test_tpm2b_public_key_rsa_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(
    TPM2B_SENSITIVE_DATA,
    test_tpm2b_sensitive_data_ffi_data_zeroize
);
implement_zeroize_test_buffer_type!(TPM2B_SYM_KEY, test_tpm2b_sym_key_ffi_data_zeroize);

implement_zeroize_test_for_named_field_structured_buffer_type!(
    TPM2B_NAME,
    name,
    test_tpm2b_name_ffi_data_zeroize
);
