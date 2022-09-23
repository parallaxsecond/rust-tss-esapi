// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.

use crate::common::{create_ctx_with_session, decryption_key_pub};
use std::convert::TryFrom;
use tss_esapi::{
    attributes::SessionAttributesBuilder,
    constants::{
        tss::{
            TSS2_BASE_RC_ABI_MISMATCH, TSS2_BASE_RC_BAD_CONTEXT, TSS2_BASE_RC_BAD_REFERENCE,
            TSS2_BASE_RC_BAD_SEQUENCE, TSS2_BASE_RC_BAD_TCTI_STRUCTURE, TSS2_BASE_RC_BAD_TEMPLATE,
            TSS2_BASE_RC_BAD_TR, TSS2_BASE_RC_BAD_VALUE, TSS2_BASE_RC_GENERAL_FAILURE,
            TSS2_BASE_RC_INCOMPATIBLE_TCTI, TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
            TSS2_BASE_RC_MALFORMED_RESPONSE, TSS2_BASE_RC_MEMORY,
            TSS2_BASE_RC_MULTIPLE_DECRYPT_SESSIONS, TSS2_BASE_RC_MULTIPLE_ENCRYPT_SESSIONS,
            TSS2_BASE_RC_NOT_IMPLEMENTED, TSS2_BASE_RC_NO_DECRYPT_PARAM,
            TSS2_BASE_RC_NO_ENCRYPT_PARAM, TSS2_BASE_RC_TRY_AGAIN, TSS2_ESYS_RC_LAYER,
        },
        BaseError, SessionType,
    },
    error::{BaseReturnCode, EsapiReturnCode, ReturnCode},
    interface_types::{algorithm::HashingAlgorithm, resource_handles::Hierarchy},
    structures::{Auth, SymmetricDefinition},
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    ($tss_rc_base_error:ident, BaseError::$base_error:ident) => {
        let expected_tss_rc = TSS2_ESYS_RC_LAYER | $tss_rc_base_error;
        let expected_base_rc = BaseReturnCode::from(BaseError::$base_error);
        let expected_esapi_rc = EsapiReturnCode::try_from(BaseError::$base_error).expect(&format!(
            "Failed to convert {} into EsapiReturnCode",
            std::stringify!(BaseError::$base_error)
        ));

        assert_eq!(
            BaseError::$base_error,
            expected_esapi_rc.into(),
            "EsapiReturnCode did not convert into the expected {}",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_esapi_rc,
            EsapiReturnCode::try_from(expected_base_rc).expect(&format!(
                "BaseReturnCode with {} failed to convert into an EsapiReturnCode",
                std::stringify!(BaseError::$base_error)
            )),
            "BaseReturnCode with {} failed to convert into the expected EsapiReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        assert_eq!(
            expected_base_rc,
            expected_esapi_rc.into(),
            "EsapiReturnCode with {} failed to convert into the expected BaseReturnCode",
            std::stringify!(BaseError::$base_error)
        );

        let actual_rc = ReturnCode::try_from(expected_tss_rc)
            .expect("Failed to convert TSS2_RC into a ReturnCode");

        if let ReturnCode::Esapi(actual_esapi_rc) = actual_rc {
            assert_eq!(
                expected_esapi_rc,
                actual_esapi_rc,
                "{} in the ESAPI layer did not convert into the expected EsapiReturnCode",
                std::stringify!($tss_rc_base_error),
            );
        } else {
            panic!("ESAPI TSS2_RC layer did no convert into ReturnCode::Esapi");
        }

        assert_eq!(
            expected_tss_rc,
            actual_rc.into(),
            "EsapiReturnCode with {} did not convert into expected {} TSS2_RC in the ESAPI layer.",
            std::stringify!(BaseError::$base_error),
            std::stringify!($tss_rc_base_error),
        );
    };
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(TSS2_BASE_RC_GENERAL_FAILURE, BaseError::GeneralFailure);
    test_valid_conversion!(TSS2_BASE_RC_NOT_IMPLEMENTED, BaseError::NotImplemented);
    test_valid_conversion!(TSS2_BASE_RC_BAD_CONTEXT, BaseError::BadContext);
    test_valid_conversion!(TSS2_BASE_RC_ABI_MISMATCH, BaseError::AbiMismatch);
    test_valid_conversion!(TSS2_BASE_RC_BAD_REFERENCE, BaseError::BadReference);
    test_valid_conversion!(TSS2_BASE_RC_BAD_SEQUENCE, BaseError::BadSequence);
    test_valid_conversion!(TSS2_BASE_RC_TRY_AGAIN, BaseError::TryAgain);
    test_valid_conversion!(TSS2_BASE_RC_BAD_VALUE, BaseError::BadValue);
    test_valid_conversion!(TSS2_BASE_RC_NO_DECRYPT_PARAM, BaseError::NoDecryptParam);
    test_valid_conversion!(TSS2_BASE_RC_NO_ENCRYPT_PARAM, BaseError::NoEncryptParam);
    test_valid_conversion!(
        TSS2_BASE_RC_MALFORMED_RESPONSE,
        BaseError::MalformedResponse
    );
    test_valid_conversion!(
        TSS2_BASE_RC_INSUFFICIENT_RESPONSE,
        BaseError::InsufficientResponse
    );
    test_valid_conversion!(TSS2_BASE_RC_INCOMPATIBLE_TCTI, BaseError::IncompatibleTcti);
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
}

#[test]
fn test_invalid_conversions() {
    let tss_invalid_fapi_rc = TSS2_ESYS_RC_LAYER | TSS2_BASE_RC_BAD_TEMPLATE;
    assert_eq!(
        ReturnCode::try_from(tss_invalid_fapi_rc),
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        "Converting invalid ESAPI layer response code did not produce the expected error"
    );
}

#[test]
fn test_esapi_error_from_context_method() {
    let mut context = create_ctx_with_session();
    let random_digest = context.get_random(16).unwrap();
    let key_auth = Auth::try_from(random_digest.as_bytes().to_vec()).unwrap();

    let first_session = context.sessions().0.expect("Missing first session");
    let second_session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )
        .expect("Failed to create second session")
        .expect("Returned invalid value for second session");
    let (second_session_attributes, second_session_attributes_mask) =
        SessionAttributesBuilder::new().with_encrypt(true).build();
    context
        .tr_sess_set_attributes(
            second_session,
            second_session_attributes,
            second_session_attributes_mask,
        )
        .expect("Failed to set attributes for second session");

    // Creating primary with two sessions that both have encrypt set.
    // This is expected to result in 'multiple encrypt sessions' ESAPI error.
    let result =
        context.execute_with_sessions((Some(first_session), Some(second_session), None), |ctx| {
            ctx.create_primary(
                Hierarchy::Owner,
                decryption_key_pub(),
                Some(key_auth.clone()),
                None,
                None,
                None,
            )
        });

    if let Err(error) = result {
        if let Error::TssError(return_code) = error {
            if let ReturnCode::Esapi(esapi_return_code) = return_code {
                assert_eq!(
                esapi_return_code.base_error(),
                BaseError::MultipleEncryptSessions,
                "Calling 'create_primary' with two encrypt session did not result in the expected ESAPI TSS error",
            );
            } else {
                panic!("Calling 'create_primary' with two encrypt session did not result in an ESAPI TSS error");
            }
        } else {
            panic!(
                "Calling 'create_primary' with two encrypt session did not result in an TSS error"
            );
        }
    } else {
        panic!("Calling 'create_primary' with two encrypt session did not result in an error");
    }
}
