#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout,
    clippy::print_stderr
)]

use disrobe_pass_native::{LeafRecovery, PseudoAbi, recover_leaf_function_abi};
use disrobe_typerec::{CIntType, TypedFunction, recover_function};

const SIGNED_AND_UNKNOWN: [u8; 29] = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x89, 0x7d, 0xf8, 0x48, 0x89, 0x75, 0xf0, 0x48, 0x8b, 0x45, 0xf8,
    0x48, 0xc1, 0xf8, 0x03, 0x48, 0x8b, 0x4d, 0xf0, 0x48, 0x01, 0xc8, 0x5d, 0xc3,
];

const ADDRESS_TAKEN: [u8; 18] = [
    0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x45, 0xf8, 0x48, 0x89, 0x4d, 0xf8, 0x48, 0x8b, 0x45, 0xf8,
    0x5d, 0xc3,
];

#[test]
fn signed_slot_is_typed_and_unknown_sign_slot_falls_back_to_word() {
    let base: u64 = 0x1000;
    let typed: TypedFunction = recover_function(&SIGNED_AND_UNKNOWN, base);
    assert_eq!(
        typed.typed_slot(-8),
        Some(CIntType::I64),
        "the arithmetic shift proves slot -8 is a signed qword; typerec must surface it",
    );
    assert_eq!(
        typed.typed_slot(-16),
        None,
        "slot -16 only feeds a sign-agnostic add; sign is undetermined and must abstain",
    );

    let rec: LeafRecovery = recover_leaf_function_abi(&SIGNED_AND_UNKNOWN, base, PseudoAbi::SysV)
        .expect("the rbp-frame spill/shift/add leaf must lift");
    let source: &str = &rec.source;
    assert!(
        source.contains("(int64_t*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-8LL)"),
        "the soundly-typed signed slot must render with its recovered int64_t type: {source}",
    );
    assert!(
        source.contains("(uint64_t*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-16LL)"),
        "the undetermined-sign slot must keep the uint64_t word type: {source}",
    );
    assert!(
        !source.contains("(int64_t*)(uintptr_t)(r_rbp + (uint64_t)(int64_t)-16LL)"),
        "the undetermined-sign slot must never be emitted as a signed type: {source}",
    );
}

#[test]
fn address_taken_slot_is_never_typed() {
    let typed: TypedFunction = recover_function(&ADDRESS_TAKEN, 0x2000);
    assert_eq!(
        typed.typed_slot(-8),
        None,
        "an address-taken slot escapes the single-object model and must not be typed",
    );
    assert!(
        typed.typed_slots().is_empty(),
        "no slot in the escaped function is soundly typeable",
    );
    assert!(
        recover_leaf_function_abi(&ADDRESS_TAKEN, 0x2000, PseudoAbi::SysV).is_err(),
        "the native frame model soundly rejects a function that takes a slot address",
    );
}
