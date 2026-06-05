#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::collections::BTreeMap;

use disrobe_pass_native::{DwarfVersion, classify_dwarf_versions};

#[test]
fn dwarf_version_histogram_groups_all_versions() {
    let hist: BTreeMap<DwarfVersion, u32> = classify_dwarf_versions(&[2, 2, 3, 4, 4, 4, 5, 99]);
    assert_eq!(hist[&DwarfVersion::V2], 2);
    assert_eq!(hist[&DwarfVersion::V3], 1);
    assert_eq!(hist[&DwarfVersion::V4], 3);
    assert_eq!(hist[&DwarfVersion::V5], 1);
    assert_eq!(hist[&DwarfVersion::Unknown], 1);
}

#[test]
#[ignore = "FIXTURE PENDING: real DWARF v2 through v5 ELF object set required"]
fn real_dwarf_v2_through_v5_sweep() {}
