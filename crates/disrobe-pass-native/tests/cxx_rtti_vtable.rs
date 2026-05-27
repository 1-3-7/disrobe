#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{RttiEntry, recover_itanium_rtti};

#[test]
fn rtti_recovery_clusters_typeinfo_vtable_typestring() {
    let syms: [&str; 3] = ["_ZTV5Class", "_ZTI5Class", "_ZTS5Class"];
    let out: Vec<RttiEntry> = recover_itanium_rtti(&syms);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].class_name, "5Class");
}
