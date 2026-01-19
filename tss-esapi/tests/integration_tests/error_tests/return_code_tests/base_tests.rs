// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.
use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_AUTHORIZATION_FAILED,
            TSS2_BASE_RC_AUTHORIZATION_UNKNOWN, TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_KEY,
            TSS2_BASE_RC_BAD_PATH, TSS2_BASE_RC_BAD_REFERENCE, TSS2_BASE_RC_BAD_SEQUENCE,
            TSS2_BASE_RC_BAD_SIZE, TSS2_BASE_RC_BAD_TCTI_STRUCTURE, TSS2_BASE_RC_BAD_TEMPLATE,
            TSS2_BASE_RC_BAD_TR, TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE,
            TSS2_BASE_RC_HASH_MISMATCH, TSS2_BASE_RC_INCOMPATIBLE_TCTI,
            TSS2_BASE_RC_INSUFFICIENT_BUFFER, TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
            TSS2_BASE_RC_INSUFFICIENT_RESPONSE, TSS2_BASE_RC_INVALID_SESSIONS,
            TSS2_BASE_RC_IO_ERROR, TSS2_BASE_RC_KEY_NOT_DUPLICABLE, TSS2_BASE_RC_KEY_NOT_FOUND,
            TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_MEMORY,
            TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS, TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
            TSS2_BASE_RC_NAME_ALREADY_EXISTS, TSS2_BASE_RC_NOT_DELETABLE,
            TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_BASE_RC_NOT_PERMITTED, TSS2_BASE_RC_NOT_SUPPORTED,
            TSS2_BASE_RC_NO_CERT, TSS2_BASE_RC_NO_CONFIG, TSS2_BASE_RC_NO_CONNECTION,
            TSS2_BASE_RC_NO_DECRYPT_PARAM, TSS2_BASE_RC_NO_ENCRYPT_PARAM, TSS2_BASE_RC_NO_HANDLE,
            TSS2_BASE_RC_NO_PCR, TSS2_BASE_RC_NO_TPM, TSS2_BASE_RC_NV_NOT_READABLE,
            TSS2_BASE_RC_NV_NOT_WRITEABLE, TSS2_BASE_RC_NV_TOO_SMALL, TSS2_BASE_RC_NV_WRONG_TYPE,
            TSS2_BASE_RC_PATH_ALREADY_EXISTS, TSS2_BASE_RC_PATH_NOT_FOUND,
            TSS2_BASE_RC_PCR_NOT_RESETTABLE, TSS2_BASE_RC_POLICY_UNKNOWN,
            TSS2_BASE_RC_RSP_AUTH_FAILED, TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
            TSS2_BASE_RC_TRY_AGAIN,
        },
        BaseError,
    },
    error::BaseReturnCode,
    tss2_esys::TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);

        assert_eq!(
            BaseError::$base_error,
            expected_base_rc.into(),
            "BaseReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            BaseError::$base_error,
            expected_base_rc.base_error(),
            "base_error() did not return the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            BaseReturnCode::try_from($tss_rc_base_error as u16).expect(&format!(
                "Failed to convert {} into a BaseReturnCode",
                std::stringify!($tss_rc_base_error)
            )),
            "{} did not convert into the expected BaseReturnCode",
            std::stringify!($tss_rc_base_error)
        );
    };
}

macro_rules! test_display_trait_impl {
    ($expected_error_message:tt, BaseError::$base_error:ident) => {
        assert_eq!(
            format!("{}", BaseReturnCode::from(BaseError::$base_error)),
            $expected_error_message,
            "BaseReturnCode with {} did not produce the expected error message",
            std::stringify!(BaseError::$base_error),
        );
    };
}

// do not interact with swtpm, can be parallel.
#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_NOT_IMPLEMENTED, BaseError::NotImplemented);
    test_valid_conversion!(TSS2_BASE_RC_BAD_CONTEXT, BaseError::BadContext);
    test_valid_conversion!(TSS2_BASE_RC_ABI_MISMATCH, BaseError::AbiMismatch);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_BUFFER,
        BaseError::InsufficientBuffer
    );
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BaseError::BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONNECTION, BaseError::NoConnection);
    test_valid_conversion!(TSS2_BASE_RC_TRY_AGAIN, BaseError::TryAgain);
    test_valid_conversion!(TSS2_BASE_RC_IO_ERROR, BaseError::IoError);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
    test_valid_conversion!(TSS2_BASE_RC_NOT_PERMITTED, BaseError::NotPermitted);
    test_valid_conversion!(TSS2_BASE_RC_INVALID_SESSIONS, BaseError::InvalidSessions);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, BaseError::NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, BaseError::NoEncryptParam);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SIZE, BaseError::BadSize);
    test_valid_conversion!(
        TSS2_BASE_RC_MALFORMED_RESPONSE,
        BaseError::MalformedResponse
    );
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_CONTEXT,
        BaseError::InsufficientContext
    );
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
        BaseError::InsufficientResponse
    );
    test_valid_conversion!(TSS2_BASE_RC_INCOMPATIBLE_TCTI, BaseError::IncompatibleTcti);
    test_valid_conversion!(TSS2_BASE_RC_NOT_SUPPORTED, BaseError::NotSupported);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TCTI_STRUCTURE, BaseError::BadTctiStructure);
    test_valid_conversion!(TSS2_BASE_RC_MEMORY, BaseError::Memory);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TR, BaseError::BadTr);
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS,
        BaseError::MultipleDecryptSessions
    );
    test_valid_conversion!(
        TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
        BaseError::MultipleEncryptSessions
    );
    test_valid_conversion!(TSS2_BASE_RC_RSP_AUTH_FAILED, BaseError::RspAuthFailed);
    test_valid_conversion!(TSS2_BASE_RC_NO_CONFIG, BaseError::NoConfig);
    test_valid_conversion!(TSS2_BASE_RC_BAD_PATH, BaseError::BadPath);
    test_valid_conversion!(TSS2_BASE_RC_NOT_DELETABLE, BaseError::NotDeletable);
    test_valid_conversion!(
        TSS2_BASE_RC_PATH_ALREADY_EXISTS,
        BaseError::PathAlreadyExists
    );
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_FOUND, BaseError::KeyNotFound);
    test_valid_conversion!(
        TSS2_BASE_RC_SIGNATURE_VERIFICATION_FAILED,
        BaseError::SignatureVerificationFailed
    );
    test_valid_conversion!(TSS2_BASE_RC_HASH_MISMATCH, BaseError::HashMismatch);
    test_valid_conversion!(TSS2_BASE_RC_KEY_NOT_DUPLICABLE, BaseError::KeyNotDuplicable);
    test_valid_conversion!(TSS2_BASE_RC_PATH_NOT_FOUND, BaseError::PathNotFound);
    test_valid_conversion!(TSS2_BASE_RC_NO_CERT, BaseError::NoCert);
    test_valid_conversion!(TSS2_BASE_RC_NO_PCR, BaseError::NoPcr);
    test_valid_conversion!(TSS2_BASE_RC_PCR_NOT_RESETTABLE, BaseError::PcrNotResettable);
    test_valid_conversion!(TSS2_BASE_RC_BAD_TEMPLATE, BaseError::BadTemplate);
    test_valid_conversion!(
        TSS2_BASE_RC_AUTHORIZATION_FAILED,
        BaseError::AuthorizationFailed
    );
    test_valid_conversion!(
        TSS2_BASE_RC_AUTHORIZATION_UNKNOWN,
        BaseError::AuthorizationUnknown
    );
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_READABLE, BaseError::NvNotReadable);
    test_valid_conversion!(TSS2_BASE_RC_NV_TOO_SMALL, BaseError::NvTooSmall);
    test_valid_conversion!(TSS2_BASE_RC_NV_NOT_WRITEABLE, BaseError::NvNotWriteable);
    test_valid_conversion!(TSS2_BASE_RC_POLICY_UNKNOWN, BaseError::PolicyUnknown);
    test_valid_conversion!(TSS2_BASE_RC_NV_WRONG_TYPE, BaseError::NvWrongType);
    test_valid_conversion!(
        TSS2_BASE_RC_NAME_ALREADY_EXISTS,
        BaseError::NameAlreadyExists
    );
    test_valid_conversion!(TSS2_BASE_RC_NO_TPM, BaseError::NoTpm);
    test_valid_conversion!(TSS2_BASE_RC_BAD_KEY, BaseError::BadKey);
    test_valid_conversion!(TSS2_BASE_RC_NO_HANDLE, BaseError::NoHandle);
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_base_rc = TSS2_LAYER_IMPLEMENTATION_SPECIFIC_OFFSET + 1;
    assert_eq!(
        BaseReturnCode::try_from(tss_invalid_base_rc as u16),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid base response code did not produce the expected error",
    );
}

#[test]
fn test_display() {
    test_display_trait_impl!("An unspecified error occurred.", BaseError::GeneralFailure);
    test_display_trait_impl!(
        "Called functionality isn't implemented.",
        BaseError::NotImplemented
    );
    test_display_trait_impl!("A context structure is bad.", BaseError::BadContext);
    test_display_trait_impl!(
        "Passed in ABI version doesn't match called module's ABI version.",
        BaseError::AbiMismatch
    );
    test_display_trait_impl!(
        "A pointer is NULL that isn't allowed to be NULL.",
        BaseError::BadReference
    );
    test_display_trait_impl!(
        "A buffer isn't large enough.",
        BaseError::InsufficientBuffer
    );
    test_display_trait_impl!(
        "Function called in the wrong order.",
        BaseError::BadSequence
    );
    test_display_trait_impl!(
        "Fails to connect to next lower layer.",
        BaseError::NoConnection
    );
    test_display_trait_impl!(
        "Operation timed out; function must be called again to be completed.",
        BaseError::TryAgain
    );
    test_display_trait_impl!("IO failure.", BaseError::IoError);
    test_display_trait_impl!("A parameter has a bad value.", BaseError::BadValue);
    test_display_trait_impl!("Operation not permitted.", BaseError::NotPermitted);
    test_display_trait_impl!(
        "The TPM command doesn't use the number of sessions provided by the caller.",
        BaseError::InvalidSessions
    );
    test_display_trait_impl!("A session with decrypt set in its SessionAttributes (TPMA_SESSION_DECRYPT bit set) was passed to a TPM command that doesn't support encryption of the first command parameter.", BaseError::NoDecryptParam);
    test_display_trait_impl!("A session with encrypt set in its SessionAttributes (TPMA_SESSION_ENCRYPT bit set) was passed to a TPM command that doesn't support encryption of the first response parameter.", BaseError::NoEncryptParam);
    test_display_trait_impl!("Size of a parameter is incorrect.", BaseError::BadSize);
    test_display_trait_impl!("Response is malformed.", BaseError::MalformedResponse);
    test_display_trait_impl!("Context not large enough.", BaseError::InsufficientContext);
    test_display_trait_impl!(
        "Response is not long enough.",
        BaseError::InsufficientResponse
    );
    test_display_trait_impl!(
        "Unknown or unusable TCTI version.",
        BaseError::IncompatibleTcti
    );
    test_display_trait_impl!("Functionality not supported.", BaseError::NotSupported);
    test_display_trait_impl!("TCTI context is bad.", BaseError::BadTctiStructure);
    test_display_trait_impl!("Memory allocation failed.", BaseError::Memory);
    test_display_trait_impl!("Invalid ObjectHandle(ESYS_TR handle).", BaseError::BadTr);
    test_display_trait_impl!(
        "More than one session with decrypt set in SessionAttributes (TPMA_SESSION_DECRYPT bit set).",
        BaseError::MultipleDecryptSessions
    );
    test_display_trait_impl!(
        "More than one session with encrypt set in SessionAttributes (TPMA_SESSION_ENCRYPT bit set).",
        BaseError::MultipleEncryptSessions
    );
    test_display_trait_impl!(
        "Authorizing the TPM response failed.",
        BaseError::RspAuthFailed
    );
    test_display_trait_impl!("No config is available.", BaseError::NoConfig);
    test_display_trait_impl!("The provided path is bad.", BaseError::BadPath);
    test_display_trait_impl!("The object is not deletable.", BaseError::NotDeletable);
    test_display_trait_impl!(
        "The provided path already exists.",
        BaseError::PathAlreadyExists
    );
    test_display_trait_impl!("The key was not found.", BaseError::KeyNotFound);
    test_display_trait_impl!(
        "Signature verification failed.",
        BaseError::SignatureVerificationFailed
    );
    test_display_trait_impl!("Hash mismatch.", BaseError::HashMismatch);
    test_display_trait_impl!("Key is not duplicatable.", BaseError::KeyNotDuplicable);
    test_display_trait_impl!("The path was not found.", BaseError::PathNotFound);
    test_display_trait_impl!("No certificate.", BaseError::NoCert);
    test_display_trait_impl!("No PCR.", BaseError::NoPcr);
    test_display_trait_impl!("PCR not resettable.", BaseError::PcrNotResettable);
    test_display_trait_impl!("The template is bad.", BaseError::BadTemplate);
    test_display_trait_impl!("Authorization failed.", BaseError::AuthorizationFailed);
    test_display_trait_impl!("Authorization is unknown.", BaseError::AuthorizationUnknown);
    test_display_trait_impl!("NV is not readable.", BaseError::NvNotReadable);
    test_display_trait_impl!("NV is too small.", BaseError::NvTooSmall);
    test_display_trait_impl!("NV is not writable.", BaseError::NvNotWriteable);
    test_display_trait_impl!("The policy is unknown.", BaseError::PolicyUnknown);
    test_display_trait_impl!("The NV type is wrong.", BaseError::NvWrongType);
    test_display_trait_impl!("The name already exists.", BaseError::NameAlreadyExists);
    test_display_trait_impl!("No TPM available.", BaseError::NoTpm);
    test_display_trait_impl!("The key is bad.", BaseError::BadKey);
    test_display_trait_impl!("No handle provided.", BaseError::NoHandle);
    test_display_trait_impl!("Provisioning was not executed.", BaseError::NotProvisioned);
    test_display_trait_impl!("Already provisioned.", BaseError::AlreadyProvisioned);
}
