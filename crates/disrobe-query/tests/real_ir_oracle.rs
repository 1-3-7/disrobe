#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreadable_literal
)]

use disrobe_binfmt::native::{NativeFile, SymbolInfo, parse_native};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnFlow, decode_disasm,
    encode_disasm,
};
use disrobe_ir::{Envelope, Rung};
use disrobe_query::{
    CallSiteMatch, CapabilitySiteMatch, DecoderMatch, FunctionMatch, Module, Query, QueryResult,
    XrefMatch, module_from_bytes,
};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter as _, Instruction, NasmFormatter, OpKind,
};
use object::write::{
    Object as WriteObject, StandardSection, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags,
    SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
};
use object::{Architecture, BinaryFormat, Endianness};

const TEXT_LEN: usize = 0x80;

const READ_BYTE: u64 = 0x00;
const DECODE: u64 = 0x10;
const DECODE_CALL_READ_BYTE: u64 = 0x13;
const CRYPTO_INIT: u64 = 0x30;
const CRYPTO_CALL: u64 = 0x30;
const NET_SEND: u64 = 0x40;
const NET_CALL_CONNECT: u64 = 0x40;
const NET_CALL_SEND: u64 = 0x45;
const MAIN: u64 = 0x50;
const MAIN_CALL_DECODE: u64 = 0x50;
const MAIN_CALL_CRYPTO: u64 = 0x55;
const MAIN_CALL_NET: u64 = 0x5A;
const SYM_CRYPT_ENCRYPT: u64 = 0x70;
const SYM_CONNECT: u64 = 0x74;
const SYM_SEND: u64 = 0x78;

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
    put(&mut t, 0x1E, &[0x83, 0xFB, 0x10]);
    put(&mut t, 0x21, &[0x7C, 0xF0]);
    put(&mut t, 0x23, &[0x5B, 0xC3]);

    call_rel32(&mut t, CRYPTO_CALL, SYM_CRYPT_ENCRYPT);
    put(&mut t, 0x35, &[0xC3]);

    call_rel32(&mut t, NET_CALL_CONNECT, SYM_CONNECT);
    call_rel32(&mut t, NET_CALL_SEND, SYM_SEND);
    put(&mut t, 0x4A, &[0xC3]);

    call_rel32(&mut t, MAIN_CALL_DECODE, DECODE);
    call_rel32(&mut t, MAIN_CALL_CRYPTO, CRYPTO_INIT);
    call_rel32(&mut t, MAIN_CALL_NET, NET_SEND);
    put(&mut t, 0x5F, &[0x31, 0xC0, 0xC3]);

    put(&mut t, SYM_CRYPT_ENCRYPT, &[0xC3]);
    put(&mut t, SYM_CONNECT, &[0xC3]);
    put(&mut t, SYM_SEND, &[0xC3]);

    t
}

fn fixture_symbols() -> Vec<(&'static str, u64, u64)> {
    vec![
        ("read_byte", READ_BYTE, 0x03),
        ("decode", DECODE, 0x15),
        ("crypto_init", CRYPTO_INIT, 0x06),
        ("net_send", NET_SEND, 0x0B),
        ("main", MAIN, 0x12),
        ("CryptEncrypt", SYM_CRYPT_ENCRYPT, 0x01),
        ("connect", SYM_CONNECT, 0x01),
        ("send", SYM_SEND, 0x01),
    ]
}

fn build_elf() -> Vec<u8> {
    let mut obj: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    let code: Vec<u8> = build_text();
    let _ = obj.append_section_data(text, &code, 16);
    let is_export = |name: &str| name == "main";
    for (name, off, size) in fixture_symbols() {
        let sym: WriteSymbol = WriteSymbol {
            name: name.as_bytes().to_vec(),
            value: off,
            size,
            kind: WriteSymbolKind::Text,
            scope: if is_export(name) {
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

fn lift_to_disasm(elf: &[u8]) -> DisasmPayload {
    let nf: NativeFile = parse_native(elf).expect("parse native");
    let text_addr: u64 = nf
        .sections
        .iter()
        .find(|s| s.name == ".text")
        .map(|s| s.address)
        .expect("text section");

    let file: object::read::File<'_> = object::read::File::parse(elf).expect("object parse");
    let text_bytes: Vec<u8> = {
        use object::Object as _;
        use object::ObjectSection as _;
        file.sections()
            .find(|s| s.name().is_ok_and(|n| n == ".text"))
            .and_then(|s| s.data().ok().map(<[u8]>::to_vec))
            .expect("text data")
    };

    let instructions: Vec<DisasmInstruction> = disasm_x86_64(&text_bytes, text_addr);

    let known: Vec<(&str, u64)> = fixture_symbols()
        .into_iter()
        .map(|(n, off, _)| (n, off + text_addr))
        .collect();
    let import_like = |name: &str| matches!(name, "CryptEncrypt" | "connect" | "send");
    let export_like = |name: &str| name == "main";
    let symbol_table: Vec<DisasmSymbol> = nf
        .symbols
        .iter()
        .filter(|s: &&SymbolInfo| known.iter().any(|(n, _)| *n == s.name))
        .map(|s: &SymbolInfo| DisasmSymbol {
            address: s.address,
            name: s.name.clone(),
            kind: if export_like(&s.name) {
                DisasmSymbolKind::Export
            } else if import_like(&s.name) {
                DisasmSymbolKind::Import
            } else {
                DisasmSymbolKind::Function
            },
        })
        .collect();

    let source_hash: [u8; 32] = *blake3::hash(elf).as_bytes();
    DisasmPayload {
        source_hash,
        instructions,
        symbol_table,
    }
}

fn disasm_x86_64(bytes: &[u8], base: u64) -> Vec<DisasmInstruction> {
    let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, base, DecoderOptions::NONE);
    let mut formatter: NasmFormatter = NasmFormatter::new();
    let mut out: Vec<DisasmInstruction> = Vec::new();
    let mut insn: Instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        let start: usize = (insn.ip().saturating_sub(base)) as usize;
        let end: usize = start + insn.len();
        let raw: Vec<u8> = bytes.get(start..end).map_or_else(Vec::new, <[u8]>::to_vec);
        let mut text: String = String::new();
        formatter.format(&insn, &mut text);
        let (mnemonic, operands): (String, Vec<String>) = split_text(&text);
        let (flow, branch_target): (InsnFlow, Option<u64>) = flow_of(&insn);
        out.push(DisasmInstruction {
            offset: insn.ip(),
            bytes: raw,
            mnemonic,
            operands,
            flow,
            branch_target,
            ..DisasmInstruction::default()
        });
    }
    out
}

fn flow_of(insn: &Instruction) -> (InsnFlow, Option<u64>) {
    let direct: bool = matches!(
        insn.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    );
    match insn.flow_control() {
        FlowControl::Call if direct => (InsnFlow::Call, Some(insn.near_branch_target())),
        FlowControl::Call | FlowControl::IndirectCall => (InsnFlow::IndirectCall, None),
        FlowControl::ConditionalBranch => {
            (InsnFlow::ConditionalBranch, Some(insn.near_branch_target()))
        }
        FlowControl::UnconditionalBranch if direct => (
            InsnFlow::UnconditionalBranch,
            Some(insn.near_branch_target()),
        ),
        FlowControl::UnconditionalBranch => (InsnFlow::UnconditionalBranch, None),
        FlowControl::IndirectBranch => (InsnFlow::IndirectBranch, None),
        FlowControl::Return => (InsnFlow::Return, None),
        FlowControl::Interrupt => (InsnFlow::Interrupt, None),
        FlowControl::Next | FlowControl::XbeginXabortXend | FlowControl::Exception => {
            (InsnFlow::Sequential, None)
        }
    }
}

fn split_text(text: &str) -> (String, Vec<String>) {
    match text.split_once(' ') {
        Some((m, ops)) => (
            m.to_owned(),
            ops.split(',').map(|s: &str| s.trim().to_owned()).collect(),
        ),
        None => (text.to_owned(), Vec::new()),
    }
}

fn loaded_module() -> Module {
    let elf: Vec<u8> = build_elf();
    let payload: DisasmPayload = lift_to_disasm(&elf);
    let hot: Vec<u8> = encode_disasm(&payload).expect("encode disasm");
    let env: Envelope = Envelope::new(Rung::Disasm, hot, Vec::new());
    let encoded: Vec<u8> = env.encode().expect("encode envelope");
    module_from_bytes(&encoded).expect("module from dr")
}

#[test]
fn fixture_disassembles_to_expected_shape() {
    let elf: Vec<u8> = build_elf();
    let payload: DisasmPayload = lift_to_disasm(&elf);
    let decoded: DisasmPayload =
        decode_disasm(&encode_disasm(&payload).expect("enc")).expect("dec");
    assert_eq!(decoded, payload);

    let at = |off: u64| -> &DisasmInstruction {
        payload
            .instructions
            .iter()
            .find(|i: &&DisasmInstruction| i.offset == off)
            .unwrap_or_else(|| panic!("no instruction at {off:#x}"))
    };
    assert_eq!(at(READ_BYTE).mnemonic, "mov");
    assert_eq!(at(DECODE_CALL_READ_BYTE).mnemonic, "call");
    assert_eq!(at(0x18).mnemonic, "xor");
    assert_eq!(at(0x21).mnemonic, "jl");
    assert_eq!(at(CRYPTO_CALL).mnemonic, "call");
    assert_eq!(at(NET_CALL_CONNECT).mnemonic, "call");
    assert_eq!(at(NET_CALL_SEND).mnemonic, "call");
    assert_eq!(at(MAIN_CALL_DECODE).mnemonic, "call");
}

#[test]
fn oracle_functions_query_finds_every_known_function() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(&module, &Query::Functions);
    let QueryResult::Functions { matches } = result else {
        panic!("wrong variant");
    };
    let mut names: Vec<String> = matches
        .iter()
        .map(|m: &FunctionMatch| m.name.clone())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["crypto_init", "decode", "main", "net_send", "read_byte"],
        "imported API stubs (CryptEncrypt/connect/send) are not local functions"
    );
    let main: &FunctionMatch = matches
        .iter()
        .find(|m: &&FunctionMatch| m.name == "main")
        .expect("main");
    assert!(main.is_export, "main must be flagged as an export");
}

#[test]
fn oracle_calls_to_read_byte_finds_exact_site() {
    let module: Module = loaded_module();
    let text_base: u64 = module.symbol_address("read_byte").expect("read_byte");
    assert_eq!(text_base, READ_BYTE, ".text base is 0 in this fixture");

    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::CallsTo {
            target: "read_byte".to_owned(),
        },
    );
    let QueryResult::CallsTo { matches, .. } = result else {
        panic!("wrong variant");
    };
    assert_eq!(
        matches.len(),
        1,
        "exactly one call to read_byte: {matches:?}"
    );
    let site: &CallSiteMatch = &matches[0];
    assert_eq!(site.caller, "decode");
    assert_eq!(site.call_offset, DECODE_CALL_READ_BYTE);
    assert_eq!(site.target_address, READ_BYTE);
}

#[test]
fn oracle_calls_to_decode_is_from_main() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::CallsTo {
            target: "decode".to_owned(),
        },
    );
    let QueryResult::CallsTo { matches, .. } = result else {
        panic!("wrong variant");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].caller, "main");
    assert_eq!(matches[0].call_offset, MAIN_CALL_DECODE);
}

#[test]
fn oracle_xrefs_to_read_byte_match_real_references() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::XrefsTo {
            symbol: "read_byte".to_owned(),
        },
    );
    let QueryResult::XrefsTo { matches, .. } = result else {
        panic!("wrong variant");
    };
    assert_eq!(
        matches.len(),
        1,
        "only the decode call references read_byte"
    );
    let x: &XrefMatch = &matches[0];
    assert_eq!(x.from_function.as_deref(), Some("decode"));
    assert_eq!(x.from_offset, DECODE_CALL_READ_BYTE);
    assert_eq!(x.mnemonic, "call");
    assert_eq!(x.to_address, READ_BYTE);
}

#[test]
fn oracle_string_decoder_detects_decode_only() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(&module, &Query::StringDecoders);
    let QueryResult::StringDecoders { matches } = result else {
        panic!("wrong variant");
    };
    let names: Vec<&str> = matches
        .iter()
        .map(|m: &DecoderMatch| m.name.as_str())
        .collect();
    assert_eq!(names, vec!["decode"], "only decode is loop+byte-xor shaped");
    let d: &DecoderMatch = &matches[0];
    assert!(d.loop_back_edges >= 1, "decode has a back edge");
    assert!(d.byte_arith_ops >= 1, "decode xors a byte");
    assert!(d.memory_ops >= 1, "decode touches memory");
}

#[test]
fn oracle_complexity_over_one_is_decode_only() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(&module, &Query::ComplexityOver { threshold: 1 });
    let QueryResult::ComplexityOver { matches, .. } = result else {
        panic!("wrong variant");
    };
    let names: Vec<&str> = matches
        .iter()
        .map(|m: &FunctionMatch| m.name.as_str())
        .collect();
    assert_eq!(names, vec!["decode"], "only decode branches: {matches:?}");
    assert_eq!(matches[0].complexity, 2);
}

#[test]
fn oracle_network_capability_sites_are_connect_and_send() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::CapabilitySites {
            capability: disrobe_query::Capability::Network,
        },
    );
    let QueryResult::CapabilitySites { matches, .. } = result else {
        panic!("wrong variant");
    };
    let sites: Vec<(u64, &str)> = matches
        .iter()
        .map(|m: &CapabilitySiteMatch| (m.offset, m.symbol.as_str()))
        .collect();
    assert_eq!(
        sites,
        vec![(NET_CALL_CONNECT, "connect"), (NET_CALL_SEND, "send")]
    );
}

#[test]
fn oracle_crypto_capability_site_is_crypt_encrypt() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::CapabilitySites {
            capability: disrobe_query::Capability::Crypto,
        },
    );
    let QueryResult::CapabilitySites { matches, .. } = result else {
        panic!("wrong variant");
    };
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].symbol, "CryptEncrypt");
    assert_eq!(matches[0].offset, CRYPTO_CALL);
    assert_eq!(matches[0].function.as_deref(), Some("crypto_init"));
}

#[test]
fn oracle_json_round_trips_for_machine_output() {
    let module: Module = loaded_module();
    let result: QueryResult = disrobe_query::run(
        &module,
        &Query::CallsTo {
            target: "read_byte".to_owned(),
        },
    );
    let json: String = serde_json::to_string(&result).expect("serialize");
    assert!(json.contains("\"query\":\"calls-to\""));
    assert!(json.contains("\"caller\":\"decode\""));
}
