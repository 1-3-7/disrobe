#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unwrap_used
)]

mod common;

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoAbi, disassemble, recover_leaf_function_in_object,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

use common::function_code;

const BOUNDS_SOURCE: &str = include_str!("fixtures/rust_panic_guard/rust_bounds_guard.rs");
const BOUNDS_OBJECT: &[u8] = include_bytes!("fixtures/rust_panic_guard/rust_bounds_guard.obj");
const LOOKALIKE_SOURCE: &str =
    include_str!("fixtures/rust_panic_guard/returning_panic_lookalike.rs");
const LOOKALIKE_OBJECT: &[u8] =
    include_bytes!("fixtures/rust_panic_guard/returning_panic_lookalike.obj");

fn demangled_symbol(name: &str) -> String {
    rustc_demangle::try_demangle(name).map_or_else(
        |_| name.to_owned(),
        |symbol: rustc_demangle::Demangle<'_>| symbol.to_string(),
    )
}

#[test]
fn rustc_bounds_panic_location_and_success_path_recover_as_a_guard() {
    assert!(BOUNDS_SOURCE.contains("values[index] + 1"));
    let object: &[u8] = BOUNDS_OBJECT;
    let file: object::File<'_> = object::File::parse(object).expect("rustc COFF parses");
    let symbols: Vec<String> = file
        .symbols()
        .filter(|symbol: &object::Symbol<'_, '_>| symbol.is_undefined())
        .filter_map(|symbol: object::Symbol<'_, '_>| symbol.name().ok())
        .map(demangled_symbol)
        .collect();
    assert!(
        symbols
            .iter()
            .any(|name: &String| name.contains("::panicking::panic_bounds_check")),
        "rustc object must carry the undefined bounds panic symbol: {symbols:?}"
    );

    let (code, base): (Vec<u8>, u64) =
        function_code(object, "rust_bounds_guard").expect("rust bounds caller symbol");
    let instructions: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("rust bounds disassembly");
    let location_lea: &DisasmInsn = instructions
        .iter()
        .find(|instruction: &&DisasmInsn| {
            instruction.mnemonic == "lea"
                && instruction.operands.starts_with("r8,")
                && instruction.bytes.starts_with(&[0x4c, 0x8d, 0x05])
        })
        .unwrap_or_else(|| {
            panic!(
                "rustc panic path must load its location into r8 with a RIP-relative lea: {instructions:?}"
            )
        });
    let caller: object::Symbol<'_, '_> = file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| symbol.name().ok() == Some("rust_bounds_guard"))
        .expect("caller symbol");
    let section_index: object::SectionIndex = caller.section_index().expect("caller section");
    let section: object::Section<'_, '_> = file
        .section_by_index(section_index)
        .expect("caller section resolves");
    let caller_start: u64 = caller.address();
    let caller_end: u64 = caller_start + code.len() as u64;
    let mut relocation_names: Vec<String> = Vec::new();
    let mut location_relocation: bool = false;
    let location_field: u64 = location_lea.address + location_lea.bytes.len() as u64 - 4;
    for (offset, relocation) in section.relocations() {
        if !(caller_start..caller_end).contains(&offset) {
            continue;
        }
        location_relocation |= offset == location_field;
        if let RelocationTarget::Symbol(symbol_index) = relocation.target() {
            let symbol: object::Symbol<'_, '_> = file
                .symbol_by_index(symbol_index)
                .expect("relocation symbol resolves");
            if let Ok(name) = symbol.name() {
                relocation_names.push(demangled_symbol(name));
            }
        }
    }
    assert!(
        location_relocation,
        "the panic-location LEA must carry a relocation"
    );
    assert!(
        relocation_names
            .iter()
            .any(|name: &String| name.contains("::panicking::panic_bounds_check")),
        "the caller must call panic_bounds_check through a relocation: {relocation_names:?}"
    );

    let first: LeafRecovery =
        recover_leaf_function_in_object(object, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover rustc bounds-check caller");
    let second: LeafRecovery =
        recover_leaf_function_in_object(object, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover rustc bounds-check caller deterministically");
    assert_eq!(first.source, second.source);
    assert!(
        first.source.contains("panic_bounds_check("),
        "{}",
        first.source
    );
    assert!(
        first
            .source
            .contains("panic_bounds_check(r_rcx, r_rdx, (const void *)(uintptr_t)r_r8)"),
        "{}",
        first.source
    );
    assert!(
        !first.source.contains("r_r8 = (uint64_t)(int64_t)0LL"),
        "the relocated panic location must not collapse to a null pointer: {}",
        first.source
    );
    assert!(
        first.source.contains("r_r8 + r_rcx * 8ULL"),
        "the successful path must retain its values pointer and index: {}",
        first.source
    );
    assert!(
        first
            .source
            .contains("r_rax = r_rax + ((uint64_t)(int64_t)1LL)"),
        "the successful path must retain the source's result increment: {}",
        first.source
    );
    assert!(first.source.contains("return"), "{}", first.source);
    assert!(!first.source.contains("goto "), "{}", first.source);
    assert!(!first.source.contains("} else {"), "{}", first.source);
}

#[test]
fn returning_local_panic_bounds_check_lookalike_stays_returning() {
    assert!(LOOKALIKE_SOURCE.contains("fn panic_bounds_check"));
    let object: &[u8] = LOOKALIKE_OBJECT;
    let (code, base): (Vec<u8>, u64) = function_code(object, "returning_panic_lookalike")
        .expect("returning lookalike caller symbol");
    let recovered: LeafRecovery =
        recover_leaf_function_in_object(object, &code, base, PseudoAbi::MsX64, &[])
            .expect("returning local lookalike remains recoverable");
    assert!(recovered.source.contains("sub_"), "{}", recovered.source);
    assert!(recovered.source.contains("return"), "{}", recovered.source);
}
