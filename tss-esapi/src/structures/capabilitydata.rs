// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::{
    constants::tss::*,
    handles::TpmHandle,
    structures::{CommandCodeList, PcrSelect, PcrSelectionList, TaggedTpmPropertyList},
    tss2_esys::*,
    Error, Result, WrapperErrorKind,
};
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::mem::size_of;

#[derive(Debug, Clone)]
pub enum CapabilityData {
    Algorithms(HashMap<TPM2_ALG_ID, TPMA_ALGORITHM>),
    Handles(Vec<TpmHandle>),
    Commands(Vec<TPMA_CC>),
    PpCommands(CommandCodeList),
    AuditCommands(CommandCodeList),
    AssignedPCR(PcrSelectionList),
    TpmProperties(TaggedTpmPropertyList),
    PCRProperties(HashMap<TPM2_PT_PCR, PcrSelect>),
    ECCCurves(Vec<TPM2_ECC_CURVE>),
    // These are in the TPM TMU_CAPABILITIES, but are not defined by esapi-2.4.1
    // AuthPolicies(),
    // ActData(),
}

fn max_cap_size<T>() -> u32 {
    ((TPM2_MAX_CAP_BUFFER as usize - size_of::<TPM2_CAP>() - size_of::<u32>()) / size_of::<T>())
        as u32
}

fn cd_from_alg_properties(props: TPML_ALG_PROPERTY) -> Result<CapabilityData> {
    if props.count > max_cap_size::<TPMS_ALG_PROPERTY>() {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    }

    let mut data = HashMap::new();

    for i in 0..props.count {
        let prop = props.algProperties[i as usize];
        let _ = data.insert(prop.alg, prop.algProperties);
    }

    Ok(CapabilityData::Algorithms(data))
}

fn cd_from_handles(props: TPML_HANDLE) -> Result<CapabilityData> {
    if props.count > max_cap_size::<TPM2_HANDLE>() {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    }

    let mut data: Vec<TpmHandle> = Vec::new();
    data.reserve_exact(props.count as usize);

    for i in 0..props.count {
        let handle: TPM2_HANDLE = props.handle[i as usize];
        data.push(handle.try_into()?);
    }

    Ok(CapabilityData::Handles(data))
}

fn cd_from_command(props: TPML_CCA) -> Result<CapabilityData> {
    if props.count > TPM2_MAX_CAP_CC {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    }

    let mut data = Vec::new();
    data.reserve_exact(props.count as usize);

    for i in 0..props.count {
        data.push(props.commandAttributes[i as usize]);
    }

    Ok(CapabilityData::Commands(data))
}

fn cd_from_pp_commands(props: TPML_CC) -> Result<CapabilityData> {
    Ok(CapabilityData::PpCommands(CommandCodeList::try_from(
        props,
    )?))
}

fn cd_from_audit_commands(props: TPML_CC) -> Result<CapabilityData> {
    Ok(CapabilityData::AuditCommands(CommandCodeList::try_from(
        props,
    )?))
}

fn cd_from_assigned_pcrs(props: TPML_PCR_SELECTION) -> Result<CapabilityData> {
    Ok(CapabilityData::AssignedPCR(props.try_into()?))
}

fn cd_from_tpm_properties(props: TPML_TAGGED_TPM_PROPERTY) -> Result<CapabilityData> {
    Ok(CapabilityData::TpmProperties(props.try_into()?))
}

fn cd_from_pcr_properties(props: TPML_TAGGED_PCR_PROPERTY) -> Result<CapabilityData> {
    if props.count > max_cap_size::<TPMS_TAGGED_PCR_SELECT>() {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    }

    let mut data = HashMap::new();

    for i in 0..props.count {
        let prop = props.pcrProperty[i as usize];

        let select = PcrSelect::try_from(TPMS_PCR_SELECT {
            sizeofSelect: prop.sizeofSelect,
            pcrSelect: prop.pcrSelect,
        })?;

        let _ = data.insert(prop.tag, select);
    }

    Ok(CapabilityData::PCRProperties(data))
}

fn cd_from_ecc_curves(props: TPML_ECC_CURVE) -> Result<CapabilityData> {
    if props.count > max_cap_size::<TPM2_ECC_CURVE>() {
        return Err(Error::WrapperError(WrapperErrorKind::InvalidParam));
    }

    let mut data = Vec::new();
    data.reserve_exact(props.count as usize);

    for i in 0..props.count {
        data.push(props.eccCurves[i as usize]);
    }

    Ok(CapabilityData::ECCCurves(data))
}

impl TryFrom<TPMS_CAPABILITY_DATA> for CapabilityData {
    type Error = Error;

    fn try_from(capab_data: TPMS_CAPABILITY_DATA) -> Result<Self> {
        // SAFETY: This is a C union, and Rust wants us to make sure we're using the correct item.
        // These unsafe blocks are fine because we ensure the correct type is used.
        match capab_data.capability {
            TPM2_CAP_ALGS => cd_from_alg_properties(unsafe { capab_data.data.algorithms }),
            TPM2_CAP_HANDLES => cd_from_handles(unsafe { capab_data.data.handles }),
            TPM2_CAP_COMMANDS => cd_from_command(unsafe { capab_data.data.command }),
            TPM2_CAP_PP_COMMANDS => cd_from_pp_commands(unsafe { capab_data.data.ppCommands }),
            TPM2_CAP_AUDIT_COMMANDS => {
                cd_from_audit_commands(unsafe { capab_data.data.auditCommands })
            }
            TPM2_CAP_PCRS => cd_from_assigned_pcrs(unsafe { capab_data.data.assignedPCR }),
            TPM2_CAP_TPM_PROPERTIES => {
                cd_from_tpm_properties(unsafe { capab_data.data.tpmProperties })
            }
            TPM2_CAP_PCR_PROPERTIES => {
                cd_from_pcr_properties(unsafe { capab_data.data.pcrProperties })
            }
            TPM2_CAP_ECC_CURVES => cd_from_ecc_curves(unsafe { capab_data.data.eccCurves }),
            _ => Err(Error::WrapperError(WrapperErrorKind::UnsupportedParam)),
        }
    }
}
