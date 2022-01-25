// Copyright 2020 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0

use std::convert::TryFrom;
use tss_esapi::{
    abstraction::nv,
    attributes::NvIndexAttributesBuilder,
    handles::{NvIndexHandle, NvIndexTpmHandle},
    interface_types::{
        algorithm::HashingAlgorithm,
        resource_handles::{NvAuth, Provision},
    },
    structures::{MaxNvBuffer, NvPublicBuilder},
    Context,
};

use crate::common::create_ctx_with_session;

fn write_nv_index(context: &mut Context, nv_index: NvIndexTpmHandle) -> NvIndexHandle {
    // Create owner nv public.
    let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
        .with_owner_write(true)
        .with_owner_read(true)
        .with_pp_read(true)
        .with_owner_read(true)
        .build()
        .expect("Failed to create owner nv index attributes");

    let owner_nv_public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(owner_nv_index_attributes)
        .with_data_area_size(1540)
        .build()
        .unwrap();

    let owner_nv_index_handle = context
        .nv_define_space(Provision::Owner, None, owner_nv_public)
        .unwrap();

    let value = [1, 2, 3, 4, 5, 6, 7];
    let expected_data = MaxNvBuffer::try_from(value.to_vec()).unwrap();

    // Write the data using Owner authorization
    context
        .nv_write(
            NvAuth::Owner,
            owner_nv_index_handle,
            expected_data.clone(),
            0,
        )
        .unwrap();
    context
        .nv_write(NvAuth::Owner, owner_nv_index_handle, expected_data, 1024)
        .unwrap();

    owner_nv_index_handle
}

#[test]
fn list() {
    let mut context = create_ctx_with_session();

    let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

    assert!(!nv::list(&mut context)
        .unwrap()
        .iter()
        .map(|(public, _)| public.nv_index())
        .any(|x| x == nv_index));

    let owner_nv_index_handle = write_nv_index(&mut context, nv_index);

    assert!(nv::list(&mut context)
        .unwrap()
        .iter()
        .map(|(public, _)| public.nv_index())
        .any(|x| x == nv_index));

    let _ = context
        .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
        .unwrap();
}

#[test]
fn read_full() {
    let mut context = create_ctx_with_session();

    let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

    let owner_nv_index_handle = write_nv_index(&mut context, nv_index);

    // Now read it back
    let read_result = nv::read_full(&mut context, NvAuth::Owner, nv_index);

    let _ = context
        .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
        .unwrap();

    let read_result = read_result.unwrap();
    assert_eq!(read_result.len(), 1540);
    assert_eq!(read_result[0..7], [1, 2, 3, 4, 5, 6, 7]);
    assert_eq!(read_result[1024..1031], [1, 2, 3, 4, 5, 6, 7]);
}
