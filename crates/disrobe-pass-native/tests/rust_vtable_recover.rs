#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{VtableEntry, recover_trait_vtables};

#[test]
fn vtable_recovery_picks_up_trait_impl_symbols() {
    let syms: [&str; 1] =
        ["_ZN54_$LT$alloc..vec..Vec$LT$T$GT$$u20$as$u20$core..fmt..Debug$GT$3fmt17h0E"];
    let out: Vec<VtableEntry> = recover_trait_vtables(&syms);
    assert_eq!(out.len(), 1);
}
