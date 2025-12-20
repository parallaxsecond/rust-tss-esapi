// Copyright 2025 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    constants::{
        tss::{
            TPM2_PT_ACTIVE_SESSIONS_MAX, TPM2_PT_ALGORITHM_SET, TPM2_PT_AUDIT_COUNTER_0,
            TPM2_PT_AUDIT_COUNTER_1, TPM2_PT_CLOCK_UPDATE, TPM2_PT_CONTEXT_GAP_MAX,
            TPM2_PT_CONTEXT_HASH, TPM2_PT_CONTEXT_SYM, TPM2_PT_CONTEXT_SYM_SIZE,
            TPM2_PT_DAY_OF_YEAR, TPM2_PT_FAMILY_INDICATOR, TPM2_PT_FIRMWARE_MAX_SVN,
            TPM2_PT_FIRMWARE_SVN, TPM2_PT_FIRMWARE_VERSION_1, TPM2_PT_FIRMWARE_VERSION_2,
            TPM2_PT_FIXED, TPM2_PT_HR_ACTIVE, TPM2_PT_HR_ACTIVE_AVAIL, TPM2_PT_HR_LOADED,
            TPM2_PT_HR_LOADED_AVAIL, TPM2_PT_HR_LOADED_MIN, TPM2_PT_HR_NV_INDEX,
            TPM2_PT_HR_PERSISTENT, TPM2_PT_HR_PERSISTENT_AVAIL, TPM2_PT_HR_PERSISTENT_MIN,
            TPM2_PT_HR_TRANSIENT_AVAIL, TPM2_PT_HR_TRANSIENT_MIN, TPM2_PT_INPUT_BUFFER,
            TPM2_PT_LEVEL, TPM2_PT_LIBRARY_COMMANDS, TPM2_PT_LOADED_CURVES,
            TPM2_PT_LOCKOUT_COUNTER, TPM2_PT_LOCKOUT_INTERVAL, TPM2_PT_LOCKOUT_RECOVERY,
            TPM2_PT_MANUFACTURER, TPM2_PT_MAX_AUTH_FAIL, TPM2_PT_MAX_CAP_BUFFER,
            TPM2_PT_MAX_COMMAND_SIZE, TPM2_PT_MAX_DIGEST, TPM2_PT_MAX_OBJECT_CONTEXT,
            TPM2_PT_MAX_RESPONSE_SIZE, TPM2_PT_MAX_SESSION_CONTEXT, TPM2_PT_MEMORY, TPM2_PT_MODES,
            TPM2_PT_NONE, TPM2_PT_NV_BUFFER_MAX, TPM2_PT_NV_COUNTERS, TPM2_PT_NV_COUNTERS_AVAIL,
            TPM2_PT_NV_COUNTERS_MAX, TPM2_PT_NV_INDEX_MAX, TPM2_PT_NV_WRITE_RECOVERY,
            TPM2_PT_ORDERLY_COUNT, TPM2_PT_PCR_COUNT, TPM2_PT_PCR_SELECT_MIN, TPM2_PT_PERMANENT,
            TPM2_PT_PS_DAY_OF_YEAR, TPM2_PT_PS_FAMILY_INDICATOR, TPM2_PT_PS_LEVEL,
            TPM2_PT_PS_REVISION, TPM2_PT_PS_YEAR, TPM2_PT_REVISION, TPM2_PT_SPLIT_MAX,
            TPM2_PT_STARTUP_CLEAR, TPM2_PT_TOTAL_COMMANDS, TPM2_PT_VAR, TPM2_PT_VENDOR_COMMANDS,
            TPM2_PT_VENDOR_STRING_1, TPM2_PT_VENDOR_STRING_2, TPM2_PT_VENDOR_STRING_3,
            TPM2_PT_VENDOR_STRING_4, TPM2_PT_VENDOR_TPM_TYPE, TPM2_PT_YEAR,
        },
        PropertyTag,
    },
    tss2_esys::TPM2_PT,
    Error, WrapperErrorKind,
};

macro_rules! test_valid_conversion {
    (PropertyTag::$item:ident, $tpm_pt:ident) => {
        assert_eq!(
            $tpm_pt,
            TPM2_PT::from(PropertyTag::$item),
            "Failed to convert {} to TPM2_PT",
            std::stringify!(PropertyTag::$item),
        );

        assert_eq!(
            PropertyTag::$item,
            PropertyTag::try_from($tpm_pt).expect(&format!(
                "Failed to convert {} to a PropertyTag",
                std::stringify!($tpm_pt)
            )),
            "{} did not convert into {}",
            std::stringify!($tpm_pt),
            std::stringify!(PropertyTag::$item),
        )
    };
}

#[test]
fn test_invalid_conversions() {
    const INVALID_PT_VALUE: TPM2_PT = 0xFFFFFFFF;
    assert_eq!(
        Err(Error::WrapperError(WrapperErrorKind::InvalidParam)),
        PropertyTag::try_from(INVALID_PT_VALUE),
        "Expected an error when converting 0xFFFFFFFF to a PropertyTag"
    );
}

#[test]
fn test_valid_conversions() {
    test_valid_conversion!(PropertyTag::None, TPM2_PT_NONE);
    test_valid_conversion!(PropertyTag::FamilyIndicator, TPM2_PT_FAMILY_INDICATOR);
    test_valid_conversion!(PropertyTag::Level, TPM2_PT_LEVEL);
    test_valid_conversion!(PropertyTag::Revision, TPM2_PT_REVISION);
    test_valid_conversion!(PropertyTag::DayOfYear, TPM2_PT_DAY_OF_YEAR);
    test_valid_conversion!(PropertyTag::Year, TPM2_PT_YEAR);
    test_valid_conversion!(PropertyTag::Manufacturer, TPM2_PT_MANUFACTURER);
    test_valid_conversion!(PropertyTag::VendorString1, TPM2_PT_VENDOR_STRING_1);
    test_valid_conversion!(PropertyTag::VendorString2, TPM2_PT_VENDOR_STRING_2);
    test_valid_conversion!(PropertyTag::VendorString3, TPM2_PT_VENDOR_STRING_3);
    test_valid_conversion!(PropertyTag::VendorString4, TPM2_PT_VENDOR_STRING_4);
    test_valid_conversion!(PropertyTag::VendorTPMType, TPM2_PT_VENDOR_TPM_TYPE);
    test_valid_conversion!(PropertyTag::FirmwareVersion1, TPM2_PT_FIRMWARE_VERSION_1);
    test_valid_conversion!(PropertyTag::FirmwareVersion2, TPM2_PT_FIRMWARE_VERSION_2);
    test_valid_conversion!(PropertyTag::InputBuffer, TPM2_PT_INPUT_BUFFER);
    test_valid_conversion!(PropertyTag::HrTransientMin, TPM2_PT_HR_TRANSIENT_MIN);
    test_valid_conversion!(PropertyTag::HrPersistentMin, TPM2_PT_HR_PERSISTENT_MIN);
    test_valid_conversion!(PropertyTag::HrLoadedMin, TPM2_PT_HR_LOADED_MIN);
    test_valid_conversion!(PropertyTag::ActiveSessionsMax, TPM2_PT_ACTIVE_SESSIONS_MAX);
    test_valid_conversion!(PropertyTag::PcrCount, TPM2_PT_PCR_COUNT);
    test_valid_conversion!(PropertyTag::PcrSelectMin, TPM2_PT_PCR_SELECT_MIN);
    test_valid_conversion!(PropertyTag::ContextGapMax, TPM2_PT_CONTEXT_GAP_MAX);
    test_valid_conversion!(PropertyTag::NvCountersMax, TPM2_PT_NV_COUNTERS_MAX);
    test_valid_conversion!(PropertyTag::NvIndexMax, TPM2_PT_NV_INDEX_MAX);
    test_valid_conversion!(PropertyTag::Memory, TPM2_PT_MEMORY);
    test_valid_conversion!(PropertyTag::ClockUpdate, TPM2_PT_CLOCK_UPDATE);
    test_valid_conversion!(PropertyTag::ContextHash, TPM2_PT_CONTEXT_HASH);
    test_valid_conversion!(PropertyTag::ContextSym, TPM2_PT_CONTEXT_SYM);
    test_valid_conversion!(PropertyTag::ContextSymSize, TPM2_PT_CONTEXT_SYM_SIZE);
    test_valid_conversion!(PropertyTag::OrderlyCount, TPM2_PT_ORDERLY_COUNT);
    test_valid_conversion!(PropertyTag::MaxCommandSize, TPM2_PT_MAX_COMMAND_SIZE);
    test_valid_conversion!(PropertyTag::MaxResponseSize, TPM2_PT_MAX_RESPONSE_SIZE);
    test_valid_conversion!(PropertyTag::MaxDigest, TPM2_PT_MAX_DIGEST);
    test_valid_conversion!(PropertyTag::MaxObjectContext, TPM2_PT_MAX_OBJECT_CONTEXT);
    test_valid_conversion!(PropertyTag::MaxSessionContext, TPM2_PT_MAX_SESSION_CONTEXT);
    test_valid_conversion!(PropertyTag::PsFamilyIndicator, TPM2_PT_PS_FAMILY_INDICATOR);
    test_valid_conversion!(PropertyTag::PsLevel, TPM2_PT_PS_LEVEL);
    test_valid_conversion!(PropertyTag::PsRevision, TPM2_PT_PS_REVISION);
    test_valid_conversion!(PropertyTag::PsDayOfYear, TPM2_PT_PS_DAY_OF_YEAR);
    test_valid_conversion!(PropertyTag::PsYear, TPM2_PT_PS_YEAR);
    test_valid_conversion!(PropertyTag::SplitMax, TPM2_PT_SPLIT_MAX);
    test_valid_conversion!(PropertyTag::TotalCommands, TPM2_PT_TOTAL_COMMANDS);
    test_valid_conversion!(PropertyTag::LibraryCommands, TPM2_PT_LIBRARY_COMMANDS);
    test_valid_conversion!(PropertyTag::VendorCommands, TPM2_PT_VENDOR_COMMANDS);
    test_valid_conversion!(PropertyTag::NvBufferMax, TPM2_PT_NV_BUFFER_MAX);
    test_valid_conversion!(PropertyTag::Modes, TPM2_PT_MODES);
    test_valid_conversion!(PropertyTag::MaxCapBuffer, TPM2_PT_MAX_CAP_BUFFER);
    test_valid_conversion!(PropertyTag::FirmwareSvn, TPM2_PT_FIRMWARE_SVN);
    test_valid_conversion!(PropertyTag::FirmwareMaxSvn, TPM2_PT_FIRMWARE_MAX_SVN);
    test_valid_conversion!(PropertyTag::Permanent, TPM2_PT_PERMANENT);
    test_valid_conversion!(PropertyTag::StartupClear, TPM2_PT_STARTUP_CLEAR);
    test_valid_conversion!(PropertyTag::HrNvIndex, TPM2_PT_HR_NV_INDEX);
    test_valid_conversion!(PropertyTag::HrLoaded, TPM2_PT_HR_LOADED);
    test_valid_conversion!(PropertyTag::HrLoadedAvail, TPM2_PT_HR_LOADED_AVAIL);
    test_valid_conversion!(PropertyTag::HrActive, TPM2_PT_HR_ACTIVE);
    test_valid_conversion!(PropertyTag::HrActiveAvail, TPM2_PT_HR_ACTIVE_AVAIL);
    test_valid_conversion!(PropertyTag::HrTransientAvail, TPM2_PT_HR_TRANSIENT_AVAIL);
    test_valid_conversion!(PropertyTag::HrPersistent, TPM2_PT_HR_PERSISTENT);
    test_valid_conversion!(PropertyTag::HrPersistentAvail, TPM2_PT_HR_PERSISTENT_AVAIL);
    test_valid_conversion!(PropertyTag::NvCounters, TPM2_PT_NV_COUNTERS);
    test_valid_conversion!(PropertyTag::NvCountersAvail, TPM2_PT_NV_COUNTERS_AVAIL);
    test_valid_conversion!(PropertyTag::AlgorithmSet, TPM2_PT_ALGORITHM_SET);
    test_valid_conversion!(PropertyTag::LoadedCurves, TPM2_PT_LOADED_CURVES);
    test_valid_conversion!(PropertyTag::LockoutCounter, TPM2_PT_LOCKOUT_COUNTER);
    test_valid_conversion!(PropertyTag::MaxAuthFail, TPM2_PT_MAX_AUTH_FAIL);
    test_valid_conversion!(PropertyTag::LockoutInterval, TPM2_PT_LOCKOUT_INTERVAL);
    test_valid_conversion!(PropertyTag::LockoutRecovery, TPM2_PT_LOCKOUT_RECOVERY);
    test_valid_conversion!(PropertyTag::WriteRecovery, TPM2_PT_NV_WRITE_RECOVERY);
    test_valid_conversion!(PropertyTag::AuditCounter0, TPM2_PT_AUDIT_COUNTER_0);
    test_valid_conversion!(PropertyTag::AuditCounter1, TPM2_PT_AUDIT_COUNTER_1);
}
