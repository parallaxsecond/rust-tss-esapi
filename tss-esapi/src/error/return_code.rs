// Copyright 2022 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

mod base;
mod esapi;
mod fapi;
mod muapi;
mod sapi;
mod tcti;
mod tpm;

use crate::{
    constants::{return_code::ReturnCodeLayer, tss::TSS2_RC_SUCCESS},
    tss2_esys::TSS2_RC,
    Error, Result,
};
pub use base::BaseReturnCode;
use bitfield::bitfield;
pub use esapi::EsapiReturnCode;
pub use fapi::FapiReturnCode;
pub use muapi::MuapiReturnCode;
pub use sapi::SapiReturnCode;
use std::convert::TryFrom;
pub use tcti::TctiReturnCode;
pub use tpm::{
    ArgumentNumber, TpmFormatOneResponseCode, TpmFormatZeroErrorResponseCode,
    TpmFormatZeroResponseCode, TpmFormatZeroWarningResponseCode, TpmResponseCode,
};

/// Enum representing return codes and response codes
/// from the TSS and the TPM that indicates an error.
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ReturnCode {
    Tpm(TpmResponseCode),
    Fapi(FapiReturnCode),
    Esapi(EsapiReturnCode),
    Sapi(SapiReturnCode),
    Mu(MuapiReturnCode),
    Tcti(TctiReturnCode),
    ResourceManager(BaseReturnCode),
    TpmResourceManager(TpmResponseCode),
}

impl ReturnCode {
    /// Ensures that the return code indicates success.
    ///
    /// # Arguments
    /// * `tss2_rc` - A TSS return code value.
    /// * `f` - Function that will be executed before an error is returned.
    ///
    /// # Errors
    /// Generates the error indicated by the return code.
    pub(crate) fn ensure_success<F>(tss2_rc: TSS2_RC, f: F) -> Result<()>
    where
        F: FnOnce(TSS2_RC),
    {
        if ReturnCodeStructure(tss2_rc).is_success() {
            Ok(())
        } else {
            f(tss2_rc);
            Err(Error::tss_error(ReturnCode::try_from(tss2_rc)?))
        }
    }
}

impl TryFrom<TSS2_RC> for ReturnCode {
    type Error = Error;
    fn try_from(tss2_rc: TSS2_RC) -> Result<Self> {
        let structure = ReturnCodeStructure(tss2_rc);
        match structure.return_code_layer()? {
            ReturnCodeLayer::Tpm => {
                TpmResponseCode::try_from(structure.return_code_data()).map(ReturnCode::Tpm)
            }
            ReturnCodeLayer::Feature => {
                FapiReturnCode::try_from(structure.return_code_data()).map(ReturnCode::Fapi)
            }
            ReturnCodeLayer::Esys => {
                EsapiReturnCode::try_from(structure.return_code_data()).map(ReturnCode::Esapi)
            }
            ReturnCodeLayer::Sys => {
                SapiReturnCode::try_from(structure.return_code_data()).map(ReturnCode::Sapi)
            }
            ReturnCodeLayer::Mu => {
                MuapiReturnCode::try_from(structure.return_code_data()).map(ReturnCode::Mu)
            }
            ReturnCodeLayer::Tcti => {
                TctiReturnCode::try_from(structure.return_code_data()).map(ReturnCode::Tcti)
            }
            ReturnCodeLayer::ResMgr => BaseReturnCode::try_from(structure.return_code_data())
                .map(ReturnCode::ResourceManager),
            ReturnCodeLayer::ResMgrTpm => TpmResponseCode::try_from(structure.return_code_data())
                .map(ReturnCode::TpmResourceManager),
        }
    }
}

impl From<ReturnCode> for TSS2_RC {
    fn from(return_code: ReturnCode) -> Self {
        let mut return_code_structure = ReturnCodeStructure(0);
        match return_code {
            ReturnCode::Tpm(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Tpm.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::Fapi(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Feature.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::Esapi(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Esys.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::Sapi(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Sys.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::Mu(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Mu.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::Tcti(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::Tcti.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::ResourceManager(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::ResMgr.into());
                return_code_structure.set_return_code_data(rc.into());
            }
            ReturnCode::TpmResourceManager(rc) => {
                return_code_structure.set_layer_data(ReturnCodeLayer::ResMgrTpm.into());
                return_code_structure.set_return_code_data(rc.into());
            }
        }
        return_code_structure.0
    }
}

impl std::error::Error for ReturnCode {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ReturnCode::Tpm(rc) => Some(rc),
            ReturnCode::Fapi(rc) => Some(rc),
            ReturnCode::Esapi(rc) => Some(rc),
            ReturnCode::Sapi(rc) => Some(rc),
            ReturnCode::Mu(rc) => Some(rc),
            ReturnCode::Tcti(rc) => Some(rc),
            ReturnCode::ResourceManager(rc) => Some(rc),
            ReturnCode::TpmResourceManager(rc) => Some(rc),
        }
    }
}

impl std::fmt::Display for ReturnCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReturnCode::Tpm(e) => write!(
                f,
                "TSS Layer: TPM, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::Fapi(e) => write!(
                f,
                "TSS Layer: FAPI, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::Esapi(e) => write!(
                f,
                "TSS Layer: ESAPI, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::Sapi(e) => write!(
                f,
                "TSS Layer: SAPI, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::Mu(e) => write!(
                f,
                "TSS Layer: MUAPI, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::Tcti(e) => write!(
                f,
                "TSS Layer: TCTI, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::ResourceManager(e) => write!(
                f,
                "TSS Layer: RESOURCE MANAGER, Code: 0x{:08X}, Message: {}",
                TSS2_RC::from(*self),
                e
            ),
            ReturnCode::TpmResourceManager(e) => {
                write!(
                    f,
                    "TSS Layer: TPM RESOURCE MANAGER, Code: 0x{:08X}, Message: {}",
                    TSS2_RC::from(*self),
                    e
                )
            }
        }
    }
}

bitfield! {
    /// A structure used for handling a TSS2_RC.
    #[derive(PartialEq, Copy, Clone)]
    struct ReturnCodeStructure(TSS2_RC);
    impl Debug;
    u8, layer_data, set_layer_data: 23, 16;
    u16, return_code_data, set_return_code_data: 15, 0;
}

impl ReturnCodeStructure {
    /// Returns the layer of the return code.
    ///
    /// # Errors
    /// If the TssReturnCodeStructure does not contain a
    /// valid layer then an error is returned.
    fn return_code_layer(&self) -> Result<ReturnCodeLayer> {
        ReturnCodeLayer::try_from(self.layer_data())
    }

    /// Checks if the return code indicates success.
    const fn is_success(&self) -> bool {
        self.0 == TSS2_RC_SUCCESS
    }
}
