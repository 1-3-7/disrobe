#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::collections::BTreeMap;

use disrobe_pass_native::{DwarfVersion, classify_dwarf_versions};
use object::{Object, ObjectSection};

const DWARF_V2: &[u8] = include_bytes!("../../../corpus/native/formats/dwarf_v2.o");
const DWARF_V3: &[u8] = include_bytes!("../../../corpus/native/formats/dwarf_v3.o");
const DWARF_V4: &[u8] = include_bytes!("../../../corpus/native/formats/dwarf_v4.o");
const DWARF_V5: &[u8] = include_bytes!("../../../corpus/native/formats/dwarf_v5.o");

#[test]
fn dwarf_version_histogram_groups_all_versions() {
    let hist: BTreeMap<DwarfVersion, u32> = classify_dwarf_versions(&[2, 2, 3, 4, 4, 4, 5, 99]);
    assert_eq!(hist[&DwarfVersion::V2], 2);
    assert_eq!(hist[&DwarfVersion::V3], 1);
    assert_eq!(hist[&DwarfVersion::V4], 3);
    assert_eq!(hist[&DwarfVersion::V5], 1);
    assert_eq!(hist[&DwarfVersion::Unknown], 1);
}

fn debug_info_version(obj_bytes: &[u8]) -> u16 {
    let file: object::File<'_> = object::File::parse(obj_bytes).expect("parse object");
    let section: object::Section<'_, '_> = file
        .section_by_name(".debug_info")
        .expect("object must carry a .debug_info section");
    let data: &[u8] = section.data().expect(".debug_info data");
    assert!(
        data.len() >= 6,
        ".debug_info must hold a CU header (unit_length + version)"
    );
    u16::from_le_bytes([data[4], data[5]])
}

#[test]
fn real_dwarf_v2_through_v5_sweep() {
    let versions: [u16; 4] = [
        debug_info_version(DWARF_V2),
        debug_info_version(DWARF_V3),
        debug_info_version(DWARF_V4),
        debug_info_version(DWARF_V5),
    ];
    assert_eq!(
        versions,
        [2, 3, 4, 5],
        "each real object must carry the DWARF version it was compiled with"
    );

    let hist: BTreeMap<DwarfVersion, u32> = classify_dwarf_versions(&versions);
    assert_eq!(hist[&DwarfVersion::V2], 1);
    assert_eq!(hist[&DwarfVersion::V3], 1);
    assert_eq!(hist[&DwarfVersion::V4], 1);
    assert_eq!(hist[&DwarfVersion::V5], 1);
    assert!(
        !hist.contains_key(&DwarfVersion::Unknown),
        "all four versions must classify to a known DWARF version"
    );

    for obj in [DWARF_V2, DWARF_V3, DWARF_V4, DWARF_V5] {
        assert!(obj.len() < 256 * 1024, "fixture under 256KB budget");
    }
}
