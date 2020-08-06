// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
use crate::tss2_esys::ESYS_TR;
use std::convert::From;

/// Representation of the most general handle
/// that is used to access esys resources.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ObjectHandle {
    value: u32,
}

impl From<ESYS_TR> for ObjectHandle {
    fn from(esys_object_handle: ESYS_TR) -> ObjectHandle {
        ObjectHandle {
            value: esys_object_handle,
        }
    }
}

impl From<ObjectHandle> for ESYS_TR {
    fn from(object_handle: ObjectHandle) -> ESYS_TR {
        object_handle.value
    }
}

/// Represents a specific esys object handle
/// used for referencing a nv index.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct NvIndexHandle {
    value: u32,
}

impl From<ObjectHandle> for NvIndexHandle {
    fn from(object_handle: ObjectHandle) -> NvIndexHandle {
        NvIndexHandle {
            value: object_handle.value,
        }
    }
}

impl From<NvIndexHandle> for ObjectHandle {
    fn from(nv_index_handle: NvIndexHandle) -> ObjectHandle {
        ObjectHandle {
            value: nv_index_handle.value,
        }
    }
}

impl From<ESYS_TR> for NvIndexHandle {
    fn from(esys_resource_handle: ESYS_TR) -> NvIndexHandle {
        NvIndexHandle {
            value: esys_resource_handle,
        }
    }
}

impl From<NvIndexHandle> for ESYS_TR {
    fn from(nv_index_handle: NvIndexHandle) -> ESYS_TR {
        nv_index_handle.value
    }
}
