// Copyright 2023 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use crate::traits::impl_mu_standard;
use tss_esapi_sys::_PRIVATE;

buffer_type!(Private, ::std::mem::size_of::<_PRIVATE>(), TPM2B_PRIVATE);

impl_mu_standard!(Private, TPM2B_PRIVATE);
