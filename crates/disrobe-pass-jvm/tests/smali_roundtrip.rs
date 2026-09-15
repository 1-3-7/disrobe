#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use disrobe_pass_jvm::{
    CodeItem, DalvikInsn, dalvik_opcode, decode_method, emit_method_body, parse_code_items,
    parse_dex,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");

fn hello_items() -> Vec<CodeItem> {
    let dex = parse_dex(HELLO_DEX).expect("parse hello.dex");
    parse_code_items(&dex, HELLO_DEX)
        .into_complete()
        .expect("fixture code items")
}

fn mnemonic_to_opcode(m: &str) -> Option<u8> {
    (0u16..=0xFF)
        .map(|o| o as u8)
        .find(|&op| dalvik_opcode(op).mnemonic == m)
}

fn reparse_mnemonics(smali: &str) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for raw in smali.lines() {
        let line: &str = raw.trim();
        if line.is_empty()
            || line.starts_with('.')
            || line.starts_with(':')
            || line.starts_with('#')
        {
            continue;
        }
        let mnemonic: &str = line.split_whitespace().next().unwrap_or("");
        let Some(op): Option<u8> = mnemonic_to_opcode(mnemonic) else {
            panic!("emitted smali line `{line}` has unrecognized mnemonic `{mnemonic}`");
        };
        out.push(dalvik_opcode(op).mnemonic);
    }
    out
}

#[test]
fn greeter_init_smali_reparses_to_same_opcode_sequence() {
    let items: Vec<CodeItem> = hello_items();
    let init: &CodeItem = items
        .iter()
        .filter(|i| i.method_name == "<init>")
        .min_by_key(|i| i.insns.len())
        .expect("Hello.dex has a <init> code_item");

    let original: Vec<&'static str> = decode_method(&init.insns)
        .iter()
        .map(|d: &DalvikInsn| d.mnemonic)
        .collect();
    assert_eq!(
        original,
        vec!["invoke-direct", "return-void"],
        "Greeter.<init> is the canonical super-ctor stub"
    );

    let smali: String = emit_method_body(init);
    assert!(smali.contains(".registers"), "body declares register count");
    assert!(smali.contains(".end method"), "body is a closed method");

    let roundtrip: Vec<&'static str> = reparse_mnemonics(&smali);
    assert_eq!(
        roundtrip, original,
        "emitted smali must re-parse to the exact opcode sequence the dex contained:\n{smali}"
    );
}

#[test]
fn every_hello_method_body_reparses_to_its_dex_opcode_sequence() {
    let items: Vec<CodeItem> = hello_items();
    assert!(!items.is_empty(), "walked Hello.dex code items");
    for item in &items {
        let original: Vec<&'static str> = decode_method(&item.insns)
            .iter()
            .map(|d: &DalvikInsn| d.mnemonic)
            .collect();
        let smali: String = emit_method_body(item);
        let roundtrip: Vec<&'static str> = reparse_mnemonics(&smali);
        assert_eq!(
            roundtrip, original,
            "textual<->binary symmetry must hold for {}.{}",
            item.class, item.method_name
        );
    }
}

#[inline]
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

#[inline]
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn uleb(b: &[u8], o: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut cursor: usize = o;
    loop {
        let byte: u8 = b[cursor];
        cursor += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, cursor)
}

fn skip_encoded_fields(b: &[u8], mut o: usize, count: u32) -> usize {
    for _ in 0..count {
        let (_d, n1): (u32, usize) = uleb(b, o);
        let (_a, n2): (u32, usize) = uleb(b, n1);
        o = n2;
    }
    o
}

fn collect_code_offsets(b: &[u8], mut o: usize, count: u32, out: &mut Vec<usize>) -> usize {
    for _ in 0..count {
        let (_d, n1): (u32, usize) = uleb(b, o);
        let (_a, n2): (u32, usize) = uleb(b, n1);
        let (code_off, n3): (u32, usize) = uleb(b, n2);
        if code_off != 0 {
            out.push(code_off as usize);
        }
        o = n3;
    }
    o
}

fn independent_reg_insn_counts(b: &[u8]) -> Vec<(u16, u32)> {
    let class_defs_size: u32 = u32_at(b, 96);
    let class_defs_off: usize = u32_at(b, 100) as usize;
    let mut code_offsets: Vec<usize> = Vec::new();
    for ci in 0..class_defs_size as usize {
        let base: usize = class_defs_off + ci * 32;
        let class_data_off: usize = u32_at(b, base + 24) as usize;
        if class_data_off == 0 {
            continue;
        }
        let (sf, n1): (u32, usize) = uleb(b, class_data_off);
        let (inf, n2): (u32, usize) = uleb(b, n1);
        let (dm, n3): (u32, usize) = uleb(b, n2);
        let (vm, n4): (u32, usize) = uleb(b, n3);
        let a1: usize = skip_encoded_fields(b, n4, sf);
        let a2: usize = skip_encoded_fields(b, a1, inf);
        let a3: usize = collect_code_offsets(b, a2, dm, &mut code_offsets);
        let _a4: usize = collect_code_offsets(b, a3, vm, &mut code_offsets);
    }
    code_offsets
        .iter()
        .map(|&off| (u16_at(b, off), u32_at(b, off + 12)))
        .collect()
}

#[test]
fn per_method_register_and_insn_counts_match_independent_dex_walk() {
    for (dex, label) in [(HELLO_DEX, "Hello"), (EDGECASES_DEX, "EdgeCases")] {
        let parsed = parse_dex(dex).expect("parse dex");
        let items: Vec<CodeItem> = parse_code_items(&parsed, dex)
            .into_complete()
            .expect("fixture code items");
        let from_parser: Vec<(u16, u32)> = items
            .iter()
            .map(|i| (i.registers_size, i.insns.len() as u32))
            .collect();
        let independent: Vec<(u16, u32)> = independent_reg_insn_counts(dex);
        assert_eq!(
            from_parser.len(),
            independent.len(),
            "{label}: parser and independent walk find the same method count"
        );
        assert_eq!(
            from_parser, independent,
            "{label}: per-method (registers_size, insns_size) must match an independent dex walk"
        );
    }
}
