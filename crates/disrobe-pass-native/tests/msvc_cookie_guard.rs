#![allow(clippy::expect_used)]

mod common;

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoAbi, disassemble, recover_leaf_function_in_object,
};
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, RelocationTarget};

use common::function_code;

const COOKIE_GUARD: &[u8] = include_bytes!("fixtures/msvc_cookie_guard/cookie_guard.obj");
const COOKIE_GUARD_SOURCE: &str = include_str!("fixtures/msvc_cookie_guard/cookie_guard.c");
const REPORT_GSFAILURE: &[u8] = include_bytes!("fixtures/msvc_cookie_guard/report_gsfailure.obj");
const REPORT_GSFAILURE_SOURCE: &str = include_str!("fixtures/msvc_cookie_guard/report_gsfailure.c");
const RETURNING_LOOKALIKE: &[u8] =
    include_bytes!("fixtures/msvc_cookie_guard/returning_lookalike.obj");
const RETURNING_LOOKALIKE_SOURCE: &str =
    include_str!("fixtures/msvc_cookie_guard/returning_lookalike.c");

fn caller_relocations<'data>(
    file: &object::File<'data>,
    caller_name: &str,
    code_len: usize,
) -> Vec<(u64, String, bool)> {
    let caller: object::Symbol<'data, '_> = file
        .symbols()
        .find(|symbol: &object::Symbol<'_, '_>| symbol.name().ok() == Some(caller_name))
        .expect("caller symbol");
    let section: object::Section<'data, '_> = file
        .section_by_index(caller.section_index().expect("caller section index"))
        .expect("caller section");
    let end: u64 = caller.address() + code_len as u64;
    section
        .relocations()
        .filter(|(offset, _): &(u64, object::Relocation)| (caller.address()..end).contains(offset))
        .filter_map(|(offset, relocation): (u64, object::Relocation)| {
            let RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                return None;
            };
            let symbol: object::Symbol<'data, '_> = file.symbol_by_index(symbol_index).ok()?;
            Some((
                offset,
                symbol.name().ok()?.to_owned(),
                symbol.is_undefined(),
            ))
        })
        .collect()
}

#[test]
fn msvc_security_cookie_plumbing_recovers_as_a_guard() {
    assert!(COOKIE_GUARD_SOURCE.contains("unsigned char buffer[32]"));
    assert!(COOKIE_GUARD_SOURCE.contains("return *buffer + 1"));
    let file: object::File<'_> = object::File::parse(COOKIE_GUARD).expect("MSVC COFF parses");
    let (code, base): (Vec<u8>, u64) =
        function_code(COOKIE_GUARD, "cookie_guard").expect("cookie guard symbol");
    let instructions: Vec<DisasmInsn> =
        disassemble(Arch::X86_64, base, &code).expect("cookie guard disassembly");
    let relocations: Vec<(u64, String, bool)> =
        caller_relocations(&file, "cookie_guard", code.len());
    assert!(
        relocations
            .iter()
            .any(|(_, name, undefined): &(u64, String, bool)| {
                name == "__security_cookie" && *undefined
            }),
        "compiler object must resolve the cookie through an undefined relocation: {relocations:?}"
    );
    assert!(
        relocations
            .iter()
            .any(|(_, name, undefined): &(u64, String, bool)| {
                name == "__security_check_cookie" && *undefined
            }),
        "compiler object must resolve the checker through an undefined relocation: {relocations:?}"
    );
    assert!(
        instructions.windows(3).any(|window: &[DisasmInsn]| {
            window[0].mnemonic == "mov"
                && window[0].operands.starts_with("rax,")
                && window[1].mnemonic == "xor"
                && window[1].operands == "rax,rsp"
                && window[2].mnemonic == "mov"
                && window[2].operands.contains("[rsp+")
                && window[2].operands.ends_with(",rax")
        }),
        "compiler object must save its rsp-mixed security cookie: {instructions:?}"
    );
    assert!(
        instructions.windows(3).any(|window: &[DisasmInsn]| {
            window[0].mnemonic == "mov"
                && window[0].operands.starts_with("rcx,[rsp+")
                && window[1].mnemonic == "xor"
                && window[1].operands == "rcx,rsp"
                && window[2].mnemonic == "call"
        }),
        "compiler object must validate its saved cookie before returning: {instructions:?}"
    );

    let first: LeafRecovery =
        recover_leaf_function_in_object(COOKIE_GUARD, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover MSVC cookie guard");
    let second: LeafRecovery =
        recover_leaf_function_in_object(COOKIE_GUARD, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover MSVC cookie guard deterministically");
    assert_eq!(first.source, second.source);
    assert!(first.source.contains("return"), "{}", first.source);
    assert!(first.source.contains("stack_frame[1]"), "{}", first.source);
    assert!(
        first.source.contains("uint64_t r_rcx = a0;"),
        "{}",
        first.source
    );
    assert!(first.source.contains("*(uint8_t*)"), "{}", first.source);
    assert!(
        first.source.contains("r_rax = (r_rax +"),
        "{}",
        first.source
    );
    assert!(
        !first.source.contains("security_cookie"),
        "{}",
        first.source
    );
    assert!(!first.source.contains("security_check"), "{}", first.source);
    assert!(
        !first.source.contains("extern void sub_"),
        "{}",
        first.source
    );
    assert!(!first.source.contains("goto "), "{}", first.source);
    assert!(!first.source.contains("} else {"), "{}", first.source);
}

#[test]
fn resolved_x64_gsfailure_import_preserves_its_cookie_argument() {
    assert!(REPORT_GSFAILURE_SOURCE.contains("uintptr_t cookie"));
    let file: object::File<'_> =
        object::File::parse(REPORT_GSFAILURE).expect("report-gsfailure COFF parses");
    let (code, base): (Vec<u8>, u64) = function_code(REPORT_GSFAILURE, "invoke_report_gsfailure")
        .expect("report-gsfailure caller symbol");
    let relocations: Vec<(u64, String, bool)> =
        caller_relocations(&file, "invoke_report_gsfailure", code.len());
    assert!(
        relocations
            .iter()
            .any(|(_, name, undefined): &(u64, String, bool)| {
                name == "__report_gsfailure" && *undefined
            }),
        "compiler object must resolve the x64 failure helper through an undefined relocation: {relocations:?}"
    );
    let first: LeafRecovery =
        recover_leaf_function_in_object(REPORT_GSFAILURE, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover report-gsfailure caller");
    let second: LeafRecovery =
        recover_leaf_function_in_object(REPORT_GSFAILURE, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover report-gsfailure caller deterministically");
    assert_eq!(first.source, second.source);
    assert!(
        first
            .source
            .contains("extern void __report_gsfailure(uintptr_t);"),
        "{}",
        first.source
    );
    assert!(
        first.source.contains("uint64_t r_rcx = a0;"),
        "{}",
        first.source
    );
    assert!(
        first
            .source
            .contains("__report_gsfailure((uintptr_t)r_rcx);"),
        "{}",
        first.source
    );
}

#[test]
fn defined_returning_gsfailure_lookalike_stays_returning() {
    assert!(RETURNING_LOOKALIKE_SOURCE.contains("return value + 3"));
    assert!(RETURNING_LOOKALIKE_SOURCE.contains("return __report_gsfailure(value) + 1"));
    let file: object::File<'_> =
        object::File::parse(RETURNING_LOOKALIKE).expect("lookalike COFF parses");
    let (code, base): (Vec<u8>, u64) =
        function_code(RETURNING_LOOKALIKE, "returning_cookie_lookalike")
            .expect("returning lookalike symbol");
    let relocations: Vec<(u64, String, bool)> =
        caller_relocations(&file, "returning_cookie_lookalike", code.len());
    assert!(
        relocations
            .iter()
            .any(|(_, name, undefined): &(u64, String, bool)| {
                name == "__report_gsfailure" && !*undefined
            }),
        "control call must resolve to a defined returning symbol: {relocations:?}"
    );
    let recovered: LeafRecovery =
        recover_leaf_function_in_object(RETURNING_LOOKALIKE, &code, base, PseudoAbi::MsX64, &[])
            .expect("recover returning lookalike");
    assert!(recovered.source.contains("sub_"), "{}", recovered.source);
    assert!(recovered.source.contains("return"), "{}", recovered.source);
}
