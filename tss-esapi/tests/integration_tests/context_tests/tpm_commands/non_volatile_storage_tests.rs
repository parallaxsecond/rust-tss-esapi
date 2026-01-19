// Copyright 2021 Contributors to the Parsec project.
// SPDX-License-Identifier: Apache-2.0
mod test_nv_define_space {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    #[serial]
    fn test_nv_define_space_failures() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500015).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Create platform nv public.
        let platform_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_platform_create(true)
            .build()
            .expect("Failed to create platform nv index attributes");

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .unwrap();

        // Fails because attributes don't match hierarchy auth.
        context
            .nv_define_space(Provision::Platform, None, owner_nv_public)
            .unwrap_err();

        context
            .nv_define_space(Provision::Owner, None, platform_nv_public)
            .unwrap_err();
    }

    #[test]
    #[serial]
    fn test_nv_define_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500016).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        // Create platform nv public.
        let platform_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_platform_create(true)
            .build()
            .expect("Failed to create platform nv index attributes");

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for platform");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // If you see this line fail, you are likely running it against a live TPM.
        // On many TPMs, you will get error 0x00000185, indicating the Platform hierarchy to
        // be unavailable (because the system went to operating system)
        let platform_nv_index_handle = context
            .nv_define_space(Provision::Platform, None, platform_nv_public)
            .expect("Call to nv_define_space failed");

        context
            .nv_undefine_space(Provision::Platform, platform_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
    }
}

mod test_nv_undefine_space {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    #[serial]
    fn test_nv_undefine_space() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500017).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Succeeds
        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
    }
}

mod test_nv_read_public {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{algorithm::HashingAlgorithm, reserved_handles::Provision},
        structures::NvPublicBuilder,
    };

    #[test]
    #[serial]
    fn test_nv_read_public() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500019).unwrap();

        let nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let expected_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build the expected NvPublic");

        let nv_index_handle = context
            .nv_define_space(Provision::Owner, None, expected_nv_public.clone())
            .expect("Call to nv_define_space failed");

        let nv_read_public_result = context.nv_read_public(nv_index_handle);

        context
            .nv_undefine_space(Provision::Owner, nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Process result
        let (actual_nv_public, _) = nv_read_public_result.expect("Call to nv_read_public failed");

        // Check result.
        assert_eq!(expected_nv_public, actual_nv_public);
    }
}

mod test_nv_write {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            reserved_handles::{NvAuth, Provision},
        },
        structures::{MaxNvBuffer, NvPublicBuilder},
    };

    #[test]
    #[serial]
    fn test_nv_write() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500018).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let data = MaxNvBuffer::try_from(vec![1, 2, 3, 4, 5, 6, 7])
            .expect("Failed to create MaxNvBuffer from vec");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Use owner authorization
        let nv_write_result = context.nv_write(NvAuth::Owner, owner_nv_index_handle, data, 0);

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        nv_write_result.expect("Call to nv_write failed");
    }
}

mod test_nv_read {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use std::convert::TryFrom;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            reserved_handles::{NvAuth, Provision},
        },
        structures::{MaxNvBuffer, NvPublicBuilder},
    };

    #[test]
    #[serial]
    fn test_nv_read() {
        let mut context = create_ctx_with_session();

        let nv_index = NvIndexTpmHandle::new(0x01500020).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let value = [1, 2, 3, 4, 5, 6, 7];
        let expected_data =
            MaxNvBuffer::try_from(value.to_vec()).expect("Failed to create MaxBuffer from data");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Write the data using Owner authorization
        let nv_write_result = context.nv_write(
            NvAuth::Owner,
            owner_nv_index_handle,
            expected_data.clone(),
            0,
        );
        // read data using owner authorization
        let nv_read_result =
            context.nv_read(NvAuth::Owner, owner_nv_index_handle, value.len() as u16, 0);
        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Process results
        nv_write_result.expect("Call to nv_write failed.");
        let actual_data = nv_read_result.expect("Call to nv_read failed.");

        // Check result.
        assert_eq!(expected_data, actual_data);
    }
}

mod test_nv_increment {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use std::convert::TryInto;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        constants::nv_index_type::NvIndexType,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            reserved_handles::{NvAuth, Provision},
        },
        structures::NvPublicBuilder,
    };

    #[test]
    #[serial]
    fn test_nv_increment() {
        let mut context = create_ctx_with_session();
        let nv_index = NvIndexTpmHandle::new(0x01500021).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_nv_index_type(NvIndexType::Counter)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(8)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Increment the counter using Owner authorization. This call initializes the counter
        let first_nv_increment_result = context.nv_increment(NvAuth::Owner, owner_nv_index_handle);

        // Read the counter using owner authorization (first call)
        let first_nv_read_result = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 8, 0);

        // Increment the counter using Owner authorization (second increment)
        let second_nv_increment_result = context.nv_increment(NvAuth::Owner, owner_nv_index_handle);

        // Read the counter using owner authorization
        let second_nv_read_result = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 8, 0);

        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Process results and report errors.
        first_nv_increment_result.expect("First call to nv_increment failed");
        let first_nv_read_value = first_nv_read_result.expect("First call to nv_read failed");
        second_nv_increment_result.expect("Second call to nv_increment failed");
        let second_nv_read_value = second_nv_read_result.expect("Second call to nv_read failed");

        // Parse the values
        // From various parts of the specification:
        // - "If nvIndexType is TPM_NT_COUNTER, TPM_NT_BITS, TPM_NT_PIN_FAIL,
        //    or TPM_NT_PIN_PASS, then publicInfo→dataSize shall be set to
        //    eight (8) or the TPM shall return TPM_RC_SIZE."
        //
        // - "NOTE 1 The NV Index counter is an unsigned value."
        //
        // - "Counter – contains an 8-octet value that is to be used as a
        //    counter and can only be modified with TPM2_NV_Increment()"
        //
        // - "Counter – an Index with an NV Index type of TPM_NT_COUNTER
        //    contains a 64-bit counter that is modified using
        //    TPM2_NV_Increment()."
        //
        // - "An integer value is considered to be an array of one or more octets.
        //    The octet at offset zero within the array is the most significant
        //    octet (MSO) of the integer. Bit number 0 of that integer is its
        //    least significant bit and is the least significant bit in the last
        //    octet in the array."
        //
        // According to the specification the index counter is an 8 byte
        // unsigned big-endian value so it will be parsed as u64.

        // Check result.
        let first_value = u64::from_be_bytes(
            first_nv_read_value
                .to_vec()
                .try_into()
                .expect("Failed to convert first_nv_read_value as a vector into an 8 byte array"),
        );
        let second_value = u64::from_be_bytes(
            second_nv_read_value
                .to_vec()
                .try_into()
                .expect("Failed to convert second_nv_read_value as a vector into an 8 byte array"),
        );

        assert_eq!(first_value + 1, second_value);
    }
}

mod test_nv_extend {
    use crate::common::create_ctx_with_session;
    use serial_test::serial;
    use tss_esapi::{
        attributes::NvIndexAttributesBuilder,
        constants::nv_index_type::NvIndexType,
        handles::NvIndexTpmHandle,
        interface_types::{
            algorithm::HashingAlgorithm,
            reserved_handles::{NvAuth, Provision},
        },
        structures::{MaxNvBuffer, NvPublicBuilder},
    };

    #[test]
    #[serial]
    fn test_nv_extend() {
        let mut context = create_ctx_with_session();
        let nv_index = NvIndexTpmHandle::new(0x01500029).unwrap();

        // Create owner nv public.
        let owner_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_orderly(true)
            .with_nv_index_type(NvIndexType::Extend)
            .build()
            .expect("Failed to create owner nv index attributes");

        let owner_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(owner_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let owner_nv_index_handle = context
            .nv_define_space(Provision::Owner, None, owner_nv_public)
            .expect("Call to nv_define_space failed");

        // Attempt to read an un-"written"/uninitialized NV index that is defined as extend type
        let nv_read_result = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 32, 0);
        assert!(nv_read_result.is_err());

        // Extend NV index with data
        let data = MaxNvBuffer::try_from(vec![0x0]).unwrap();
        context
            .nv_extend(NvAuth::Owner, owner_nv_index_handle, data)
            .expect("Failed to extend NV index");

        // Validate the new state of the index, which was extended by the data
        let nv_read_result = context.nv_read(NvAuth::Owner, owner_nv_index_handle, 32, 0);
        let read_data = nv_read_result.expect("Call to nv_read failed");

        // Expected value is sha256([0; 32] + [0; 1])
        assert_eq!(
            [
                0x7f, 0x9c, 0x9e, 0x31, 0xac, 0x82, 0x56, 0xca, 0x2f, 0x25, 0x85, 0x83, 0xdf, 0x26,
                0x2d, 0xbc, 0x7d, 0x6f, 0x68, 0xf2, 0xa0, 0x30, 0x43, 0xd5, 0xc9, 0x9a, 0x4a, 0xe5,
                0xa7, 0x39, 0x6c, 0xe9
            ],
            read_data.as_ref()
        );

        // Clean up defined NV index
        context
            .nv_undefine_space(Provision::Owner, owner_nv_index_handle)
            .expect("Call to nv_undefine_space failed");

        // Create platform nv public that is cleared on TPM reset/shutdown
        let platform_nv_index_attributes = NvIndexAttributesBuilder::new()
            .with_pp_write(true)
            .with_pp_read(true)
            .with_orderly(true)
            .with_platform_create(true)
            .with_nv_index_type(NvIndexType::Extend)
            .with_clear_stclear(true)
            .build()
            .expect("Failed to create owner nv index attributes");

        let platform_nv_public = NvPublicBuilder::new()
            .with_nv_index(nv_index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(platform_nv_index_attributes)
            .with_data_area_size(32)
            .build()
            .expect("Failed to build NvPublic for owner");

        let platform_nv_index_handle = context
            .nv_define_space(Provision::Platform, None, platform_nv_public)
            .expect("Call to nv_define_space failed");

        // Attempt to read an un-"written"/uninitialized NV index that is defined as extend type
        let nv_read_result = context.nv_read(NvAuth::Platform, platform_nv_index_handle, 32, 0);
        assert!(nv_read_result.is_err());

        // Extend NV index with data
        let data = MaxNvBuffer::try_from(vec![0x0]).unwrap();
        context
            .nv_extend(NvAuth::Platform, platform_nv_index_handle, data)
            .expect("Failed to extend NV index");

        // Validate the new state of the index, which was extended by the data
        let nv_read_result = context.nv_read(NvAuth::Platform, platform_nv_index_handle, 32, 0);
        let read_data = nv_read_result.expect("Call to nv_read failed");

        // Expected value is sha256([0; 32] + [0; 1])
        assert_eq!(
            [
                0x7f, 0x9c, 0x9e, 0x31, 0xac, 0x82, 0x56, 0xca, 0x2f, 0x25, 0x85, 0x83, 0xdf, 0x26,
                0x2d, 0xbc, 0x7d, 0x6f, 0x68, 0xf2, 0xa0, 0x30, 0x43, 0xd5, 0xc9, 0x9a, 0x4a, 0xe5,
                0xa7, 0x39, 0x6c, 0xe9
            ],
            read_data.as_ref()
        );

        // Clean up defined NV index
        context
            .nv_undefine_space(Provision::Platform, platform_nv_index_handle)
            .expect("Call to nv_undefine_space failed");
    }
}
