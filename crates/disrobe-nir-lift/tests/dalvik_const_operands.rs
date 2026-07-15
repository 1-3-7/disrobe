#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::{dalvik_function_address, lift_dex};
use disrobe_pass_jvm::{CodeItem, DalvikInsn, DexFile, decode_method, parse_code_items, parse_dex};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGE_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGE_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");
const WIDGET_R8_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/obfuscators/r8/Widget-r8.dex");

const FIXTURES: [(&str, &[u8]); 4] = [
    ("Hello.dex", HELLO_DEX),
    ("EdgeCases.dex", EDGE_DEX),
    ("EdgeCasesKt.dex", EDGE_KT_DEX),
    ("obfuscators/r8/Widget-r8.dex", WIDGET_R8_DEX),
];

const fn is_const(op: u8) -> bool {
    matches!(op, 0x12..=0x1C)
}

fn independent_operand(insn: &DalvikInsn, dex: &DexFile) -> Vec<String> {
    match insn.op {
        0x15 => insn
            .literal
            .map_or_else(Vec::new, |raw: i64| vec![(raw << 16).to_string()]),
        0x19 => insn
            .literal
            .map_or_else(Vec::new, |raw: i64| vec![(raw << 48).to_string()]),
        0x1A | 0x1B => insn
            .index
            .and_then(|index: u32| dex.strings.get(index as usize))
            .map_or_else(Vec::new, |text: &String| vec![text.clone()]),
        0x1C => insn
            .index
            .and_then(|index: u32| dex.type_names.get(index as usize))
            .map_or_else(Vec::new, |text: &String| vec![text.clone()]),
        _ => insn
            .literal
            .map_or_else(Vec::new, |value: i64| vec![value.to_string()]),
    }
}

fn oracle_operands(bytes: &[u8]) -> BTreeMap<u64, Vec<String>> {
    let dex: DexFile = parse_dex(bytes).expect("parse dex");
    let items: Vec<CodeItem> = parse_code_items(&dex, bytes);
    let mut out: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let method_index: u32 = u32::try_from(index).unwrap_or(u32::MAX);
        let base: u64 = dalvik_function_address(method_index);
        for insn in decode_method(&item.insns) {
            let insn: DalvikInsn = insn;
            if is_const(insn.op) {
                let address: u64 = base.saturating_add(u64::from(insn.pc));
                out.insert(address, independent_operand(&insn, &dex));
            }
        }
    }
    out
}

fn lifted_const_operands(bytes: &[u8]) -> BTreeMap<u64, Vec<String>> {
    let module: NirModule = lift_dex(bytes).expect("lift dex to NIR");
    let mut out: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for function in &module.functions {
        for instr in &function.instructions {
            if instr.op == NirOp::Const {
                out.insert(instr.address, instr.operands.clone());
            }
        }
    }
    out
}

#[test]
fn every_lifted_dalvik_const_carries_its_immediate() {
    let mut total: usize = 0;
    for (name, bytes) in FIXTURES {
        let oracle: BTreeMap<u64, Vec<String>> = oracle_operands(bytes);
        let lifted: BTreeMap<u64, Vec<String>> = lifted_const_operands(bytes);
        assert_eq!(
            lifted, oracle,
            "every lifted const in {name} must equal the value decoded from the dex operand bytes and string/type pool"
        );
        total += oracle.len();
        for (address, operand) in &oracle {
            assert_eq!(
                operand.len(),
                1,
                "the dex fixture carries a decodable immediate for the const at {address:#x} in {name}"
            );
        }
    }
    assert!(
        total >= 400,
        "the fixtures must exercise many dalvik constants: {total}"
    );
}

#[test]
fn dalvik_const_operand_range_is_covered() {
    let mut opcodes: BTreeSet<u8> = BTreeSet::new();
    for (_, bytes) in FIXTURES {
        let dex: DexFile = parse_dex(bytes).expect("parse dex");
        let items: Vec<CodeItem> = parse_code_items(&dex, bytes);
        for item in &items {
            for insn in decode_method(&item.insns) {
                let insn: DalvikInsn = insn;
                if is_const(insn.op) {
                    opcodes.insert(insn.op);
                }
            }
        }
    }
    for expected in [0x12, 0x13, 0x14, 0x15, 0x16, 0x18, 0x19, 0x1A, 0x1C] {
        assert!(
            opcodes.contains(&expected),
            "fixtures must exercise const opcode {expected:#x}: {opcodes:?}"
        );
    }
}

#[test]
fn known_floating_point_and_magic_constants_survive_the_lift() {
    let mut values: BTreeSet<String> = BTreeSet::new();
    for (_, bytes) in FIXTURES {
        for operand in lifted_const_operands(bytes).into_values() {
            values.extend(operand);
        }
    }
    for expected in [
        "4614256656552045848",
        "4607182418800017408",
        "4611686018427387904",
        "4602678819172646912",
        "9221120237041090560",
        "-889275714",
        "-2147483648",
        "LEdgeCases$Circle;",
        "Ljava/lang/Integer;",
    ] {
        assert!(
            values.contains(expected),
            "the source declares the constant {expected}; lifted consts were {values:?}"
        );
    }
}

#[test]
fn dalvik_string_constants_are_resolved_through_the_pool() {
    let mut strings: BTreeSet<String> = BTreeSet::new();
    let dex: DexFile = parse_dex(EDGE_KT_DEX).expect("parse dex");
    let items: Vec<CodeItem> = parse_code_items(&dex, EDGE_KT_DEX);
    for item in &items {
        for insn in decode_method(&item.insns) {
            let insn: DalvikInsn = insn;
            if matches!(insn.op, 0x1A | 0x1B)
                && let Some(index) = insn.index
                && let Some(text) = dex.strings.get(index as usize)
            {
                strings.insert(text.clone());
            }
        }
    }
    assert!(
        strings.len() >= 20,
        "EdgeCasesKt.dex must load many string constants: {}",
        strings.len()
    );

    let lifted: BTreeSet<String> = lifted_const_operands(EDGE_KT_DEX)
        .into_values()
        .flatten()
        .collect();
    for text in &strings {
        assert!(
            lifted.contains(text),
            "const-string {text:?} must reach the lifted NIR"
        );
    }
}
