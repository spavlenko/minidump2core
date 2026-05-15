use std::collections::BTreeMap;

use md2core::augment::add_data_to_mapping;
use md2core::model::{Mapping, MappingPermissions};
use proptest::prelude::*;

#[test]
fn add_data_splits_existing_file_mapping_at_page_boundary() {
    let mut mappings = BTreeMap::new();
    let mapping = Mapping::new(0x1000, 0x5000, MappingPermissions::new(true, false, true))
        .unwrap_or_else(|err| panic!("{err}"))
        .with_file("/lib/libc.so".to_owned(), 0);
    mappings.insert(mapping.start_address, mapping);

    add_data_to_mapping(&mut mappings, b"stack", 0x3200, 4096)
        .unwrap_or_else(|err| panic!("{err}"));

    assert_eq!(
        mappings.get(&0x1000).map(|mapping| mapping.end_address),
        Some(0x3000)
    );
    let data_mapping = mappings
        .get(&0x3000)
        .unwrap_or_else(|| panic!("missing data mapping"));
    assert_eq!(data_mapping.offset, 0x2000);
    assert_eq!(&data_mapping.data[0x200..0x205], b"stack");
    assert_eq!(data_mapping.data.len() % 4096, 0);
    // Group 9: verify end_address and permissions of the data mapping.
    // The data mapping inherits the original mapping's end_address (0x5000)
    // because add_data_to_mapping only adjusts start_address, not end_address,
    // when splitting an existing mapping.
    assert_eq!(
        data_mapping.end_address, 0x5000,
        "data mapping end_address should equal the original mapping's end_address"
    );
    // The data mapping inherits permissions from the original mapping (r-xp).
    assert!(
        data_mapping.permissions.is_readable(),
        "data mapping should be readable"
    );
    assert!(
        !data_mapping.permissions.is_writable(),
        "data mapping should not be writable"
    );
    assert!(
        data_mapping.permissions.is_executable(),
        "data mapping should be executable"
    );
}

proptest! {
    #[test]
    fn synthetic_mapping_data_is_page_aligned(address in 0u64..0x0010_0000, data in proptest::collection::vec(any::<u8>(), 0..8192)) {
        let mut mappings = BTreeMap::new();
        add_data_to_mapping(&mut mappings, &data, address, 4096)
            .map_err(|err| TestCaseError::fail(err.to_string()))?;

        let aligned = address - (address % 4096);
        let mapping = mappings
            .get(&aligned)
            .ok_or_else(|| TestCaseError::fail("missing aligned mapping"))?;
        let prefix = usize::try_from(address - aligned)
            .map_err(|err| TestCaseError::fail(err.to_string()))?;
        prop_assert_eq!(mapping.data.len() % 4096, 0);
        prop_assert_eq!(&mapping.data[prefix..prefix + data.len()], data.as_slice());
    }
}
