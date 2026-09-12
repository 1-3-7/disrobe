#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreadable_literal
)]

use disrobe_ir::payload::DisasmPayload;
use disrobe_pass_native::build_disasm_payload;
use disrobe_query::{CallSiteMatch, FunctionMatch, Module, Query, QueryResult, XrefMatch};
use object::write::{
    Object as WriteObject, StandardSection, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags,
    SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
};
use object::{Architecture, BinaryFormat, Endianness};

const TEXT_LEN: usize = 0x60;
const READ_BYTE: u64 = 0x00;
const DECODE: u64 = 0x10;
const DECODE_CALL_READ_BYTE: u64 = 0x13;
const MAIN: u64 = 0x40;
const MAIN_CALL_DECODE: u64 = 0x40;

fn put(buf: &mut [u8], at: u64, bytes: &[u8]) {
    let start: usize = at as usize;
    buf[start..start + bytes.len()].copy_from_slice(bytes);
}

fn call_rel32(buf: &mut [u8], at: u64, target: u64) {
    let next: i64 = at as i64 + 5;
    let rel: i32 = i32::try_from(target as i64 - next).expect("rel32 fits");
    buf[at as usize] = 0xE8;
    buf[at as usize + 1..at as usize + 5].copy_from_slice(&rel.to_le_bytes());
}

fn build_text() -> Vec<u8> {
    let mut t: Vec<u8> = vec![0xCC; TEXT_LEN];
    put(&mut t, READ_BYTE, &[0x8A, 0x07, 0xC3]);

    put(&mut t, DECODE, &[0x53, 0x31, 0xDB]);
    call_rel32(&mut t, DECODE_CALL_READ_BYTE, READ_BYTE);
    put(&mut t, 0x18, &[0x34, 0x5A]);
    put(&mut t, 0x1A, &[0x88, 0x04, 0x1F]);
    put(&mut t, 0x1D, &[0x43]);
    put(&mut t, 0x1E, &[0x83, 0xFB, 0x20]);
    put(&mut t, 0x21, &[0x7C, 0xF0]);
    put(&mut t, 0x23, &[0x5B, 0xC3]);

    call_rel32(&mut t, MAIN_CALL_DECODE, DECODE);
    put(&mut t, 0x45, &[0x31, 0xC0, 0xC3]);
    t
}

fn build_elf() -> Vec<u8> {
    let mut obj: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    let _ = obj.append_section_data(text, &build_text(), 16);
    let symbols: [(&str, u64, u64, bool); 3] = [
        ("read_byte", READ_BYTE, 0x03, false),
        ("decode", DECODE, 0x15, false),
        ("main", MAIN, 0x06, true),
    ];
    for (name, off, size, export) in symbols {
        let sym: WriteSymbol = WriteSymbol {
            name: name.as_bytes().to_vec(),
            value: off,
            size,
            kind: WriteSymbolKind::Text,
            scope: if export {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Linkage
            },
            weak: false,
            section: SymbolSection::Section(text),
            flags: WriteSymbolFlags::None,
        };
        let _ = obj.add_symbol(sym);
    }
    obj.write().expect("elf write")
}

fn run_pass(elf: &[u8]) -> Module {
    let payload: DisasmPayload = build_disasm_payload(elf).expect("build disasm payload");
    Module::from_disasm(&payload)
}

#[test]
fn production_pass_emits_a_queryable_disasm_module() {
    let elf: Vec<u8> = build_elf();
    let module: Module = run_pass(&elf);
    assert!(
        !module.functions().is_empty(),
        "the production pass must surface real functions"
    );
}

#[test]
fn e2e_functions_query_returns_real_functions() {
    let elf: Vec<u8> = build_elf();
    let module: Module = run_pass(&elf);

    let result: QueryResult = disrobe_query::run(&module, &Query::Functions);
    let QueryResult::Functions { matches } = result else {
        panic!("wrong variant");
    };
    let names: Vec<&str> = matches
        .iter()
        .map(|m: &FunctionMatch| m.name.as_str())
        .collect();
    assert!(names.contains(&"read_byte"), "functions: {names:?}");
    assert!(names.contains(&"decode"), "functions: {names:?}");
    assert!(names.contains(&"main"), "functions: {names:?}");
    let main: &FunctionMatch = matches
        .iter()
        .find(|m: &&FunctionMatch| m.name == "main")
        .expect("main");
    assert!(main.is_export, "main must be flagged export end to end");
}

#[test]
fn e2e_calls_to_and_xrefs_resolve_real_sites() {
    let elf: Vec<u8> = build_elf();
    let module: Module = run_pass(&elf);

    let calls: QueryResult = disrobe_query::run(
        &module,
        &Query::CallsTo {
            target: "read_byte".to_owned(),
        },
    );
    let QueryResult::CallsTo { matches, .. } = calls else {
        panic!("wrong variant");
    };
    assert_eq!(matches.len(), 1, "one call to read_byte: {matches:?}");
    let site: &CallSiteMatch = &matches[0];
    assert_eq!(site.caller, "decode");
    assert_eq!(site.call_offset, DECODE_CALL_READ_BYTE);

    let xrefs: QueryResult = disrobe_query::run(
        &module,
        &Query::XrefsTo {
            symbol: "decode".to_owned(),
        },
    );
    let QueryResult::XrefsTo { matches, .. } = xrefs else {
        panic!("wrong variant");
    };
    assert_eq!(matches.len(), 1, "one xref to decode: {matches:?}");
    let x: &XrefMatch = &matches[0];
    assert_eq!(x.from_function.as_deref(), Some("main"));
    assert_eq!(x.from_offset, MAIN_CALL_DECODE);
    assert_eq!(x.mnemonic, "call");
}

#[test]
fn e2e_complexity_and_string_decoder_match_decode() {
    let elf: Vec<u8> = build_elf();
    let module: Module = run_pass(&elf);

    let complexity: QueryResult =
        disrobe_query::run(&module, &Query::ComplexityOver { threshold: 1 });
    let QueryResult::ComplexityOver { matches, .. } = complexity else {
        panic!("wrong variant");
    };
    let names: Vec<&str> = matches
        .iter()
        .map(|m: &FunctionMatch| m.name.as_str())
        .collect();
    assert_eq!(names, vec!["decode"], "only decode branches: {matches:?}");

    let decoders: QueryResult = disrobe_query::run(&module, &Query::StringDecoders);
    let QueryResult::StringDecoders { matches } = decoders else {
        panic!("wrong variant");
    };
    assert_eq!(matches.len(), 1, "only decode is decoder-shaped");
    assert_eq!(matches[0].name, "decode");
}
