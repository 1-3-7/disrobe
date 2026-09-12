#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{MonomorphizationGroup, group_monomorphizations};

#[test]
fn generic_origins_group_monomorphizations() {
    let syms: [&str; 3] = [
        "core::option::Option$LT$u32$GT$::unwrap",
        "core::option::Option$LT$u64$GT$::unwrap",
        "core::option::Option$LT$bool$GT$::unwrap",
    ];
    let groups: Vec<MonomorphizationGroup> = group_monomorphizations(&syms);
    assert_eq!(groups.len(), 1);
    assert!(groups[0].generic_origin.contains("Option"));
    assert_eq!(groups[0].instances.len(), 3);
}
