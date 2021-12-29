// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::{convert::TryFrom, io::Read};

use crate::{
    constants::{tss::*, CapabilityType, PropertyTag},
    handles::{NvIndexHandle, NvIndexTpmHandle, TpmHandle},
    interface_types::resource_handles::NvAuth,
    structures::{CapabilityData, MaxNvBuffer, Name, NvPublic},
    Context, Error, Result, WrapperErrorKind,
};

/// Allows reading an NV Index completely, regardless of the max TPM NV buffer size
pub fn read_full(
    context: &mut Context,
    auth_handle: NvAuth,
    nv_index_handle: NvIndexTpmHandle,
) -> Result<Vec<u8>> {
    let mut rw = NvOpenOptions::new().open(context, auth_handle, nv_index_handle)?;
    let mut result = Vec::with_capacity(rw.size());

    let _ = rw.read_to_end(&mut result).map_err(|e| {
        // Try to convert the error back into a tss-esapi::Error if it was one originally
        match e.into_inner() {
            None => Error::WrapperError(WrapperErrorKind::InvalidParam),
            Some(e) => match e.downcast::<Error>() {
                Ok(e) => *e,
                Err(_) => Error::WrapperError(WrapperErrorKind::InvalidParam),
            },
        }
    })?;

    Ok(result)
}

/// Returns the NvPublic and Name associated with an NV index TPM handle
fn get_nv_index_info(
    context: &mut Context,
    nv_index_tpm_handle: NvIndexTpmHandle,
) -> Result<(NvPublic, Name)> {
    context
        .tr_from_tpm_public(nv_index_tpm_handle.into())
        .and_then(|mut object_handle| {
            context
                .nv_read_public(NvIndexHandle::from(object_handle))
                .map_err(|e| {
                    let _ = context.tr_close(&mut object_handle);
                    e
                })
                .and_then(|(nv_public, name)| {
                    context.tr_close(&mut object_handle)?;
                    Ok((nv_public, name))
                })
        })
}

/// Lists all the currently defined NV Indexes' names and public components
pub fn list(context: &mut Context) -> Result<Vec<(NvPublic, Name)>> {
    context.execute_without_session(|ctx| {
        ctx.get_capability(
            CapabilityType::Handles,
            TPM2_NV_INDEX_FIRST,
            TPM2_PT_NV_INDEX_MAX,
        )
        .and_then(|(capability_data, _)| match capability_data {
            CapabilityData::Handles(tpm_handles) => Ok(tpm_handles),
            _ => Err(Error::local_error(WrapperErrorKind::WrongValueFromTpm)),
        })
        .and_then(|tpm_handles| {
            tpm_handles
                .iter()
                .map(|&tpm_handle| get_nv_index_info(ctx, NvIndexTpmHandle::try_from(tpm_handle)?))
                .collect()
        })
    })
}

/// Options and flags which can be used to determine how a non-volatile storage index is opened.
///
/// This builder exposes the ability to determine how a [`NvReaderWriter`] is opened, and is typically used by
/// calling [`NvOpenOptions::new`], chaining method calls to set each option and then calling [`NvOpenOptions::open`].
#[derive(Debug, Clone, Default)]
// The type is going to get more complex in the future
#[allow(missing_copy_implementations)]
pub struct NvOpenOptions {}

impl NvOpenOptions {
    /// Creates a new blank set of options for opening a non-volatile storage index
    ///
    /// All options are initially set to `false`/`None`.
    pub fn new() -> Self {
        Self {}
    }

    /// Opens a non-volatile storage index using the options specified by `self`
    ///
    /// The non-volatile storage index may be used for reading or writing or both.
    pub fn open<'a>(
        &self,
        context: &'a mut Context,
        auth_handle: NvAuth,
        nv_index_handle: NvIndexTpmHandle,
    ) -> Result<NvReaderWriter<'a>> {
        let buffer_size = context
            .get_tpm_property(PropertyTag::NvBufferMax)?
            .unwrap_or(MaxNvBuffer::MAX_SIZE as u32) as usize;

        let nv_idx = TpmHandle::NvIndex(nv_index_handle);
        let nv_idx = context
            .execute_without_session(|ctx| ctx.tr_from_tpm_public(nv_idx))?
            .into();
        let data_size = context
            .execute_without_session(|ctx| ctx.nv_read_public(nv_idx))
            .map(|(nvpub, _)| nvpub.data_size())?;

        Ok(NvReaderWriter {
            context,
            auth_handle,
            buffer_size,
            nv_idx,
            data_size,
            offset: 0,
        })
    }
}

/// Non-volatile storage index reader/writer
///
/// Provides methods and trait implementations to interact with a non-volatile storage index that has been opened.
///
/// Use [`NvOpenOptions::open`] to obtain an [`NvReaderWriter`] object.
#[derive(Debug)]
pub struct NvReaderWriter<'a> {
    context: &'a mut Context,
    auth_handle: NvAuth,

    buffer_size: usize,
    nv_idx: NvIndexHandle,
    data_size: usize,
    offset: usize,
}

impl NvReaderWriter<'_> {
    /// The size of the data in the non-volatile storage index
    pub fn size(&self) -> usize {
        self.data_size
    }
}

impl Read for NvReaderWriter<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.data_size <= self.offset {
            return Ok(0);
        }

        let desired_size = std::cmp::min(buf.len(), self.data_size - self.offset);
        let size: u16 = std::cmp::min(self.buffer_size, desired_size) as u16;

        let res = self
            .context
            .nv_read(self.auth_handle, self.nv_idx, size, self.offset as u16)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        buf[0..size as usize].copy_from_slice(&res);
        self.offset += size as usize;

        Ok(size.into())
    }
}

impl Drop for NvReaderWriter<'_> {
    fn drop(&mut self) {
        let mut obj_handle = self.nv_idx.into();
        let _ = self
            .context
            .execute_without_session(|ctx| ctx.tr_close(&mut obj_handle));
    }
}
