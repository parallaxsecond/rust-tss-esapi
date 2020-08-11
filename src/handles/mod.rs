// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

/// Module that contains the different types of handles
/// that the ESAPI and the TPM uses in order to provide
/// access to objects that was or has been created.

/////////////////////////////////////////////////////////
/// ESYS Handles
/////////////////////////////////////////////////////////
pub use handle::auth::AuthHandle;
pub use handle::key::KeyHandle;
pub use handle::nv_index::NvIndexHandle;
pub use handle::object::ObjectHandle;
pub use handle::pcr::PcrHandle;
pub use handle::session::SessionHandle;
pub use handle::tpm_constants::TpmConstantsHandle;
mod handle;
/////////////////////////////////////////////////////////
/// TPM Handles
/////////////////////////////////////////////////////////
pub use tpm::AcTpmHandle;
pub use tpm::HmacSessionTpmHandle;
pub use tpm::LoadedSessionTpmHandle;
pub use tpm::NvIndexTpmHandle;
pub use tpm::PcrTpmHandle;
pub use tpm::PermanentTpmHandle;
pub use tpm::PersistentTpmHandle;
pub use tpm::PolicySessionTpmHandle;
pub use tpm::SavedSessionTpmHandle;
pub use tpm::TpmHandle;
pub use tpm::TransientTpmHandle;
mod tpm;
