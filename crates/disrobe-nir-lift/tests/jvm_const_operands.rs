#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::lift_classfile;
use disrobe_pass_jvm::{
    Attribute, ClassFile, CodeAttribute, ConstantPoolEntry, Instruction, Operands, disassemble,
    parse_classfile, parse_code_attribute,
};

const STRINGER: &[u8] = include_bytes!("../../../corpus/jvm/stringer/StringerClassic.class");

fn ldc_render(class: &ClassFile, index: u16) -> Option<String> {
    match class.constant_pool.get(usize::from(index)) {
        Some(ConstantPoolEntry::Integer(v)) => Some(v.to_string()),
        Some(ConstantPoolEntry::Long(v)) => Some(v.to_string()),
        Some(ConstantPoolEntry::Float(bits)) => Some(f32::from_bits(*bits).to_string()),
        Some(ConstantPoolEntry::Double(bits)) => Some(f64::from_bits(*bits).to_string()),
        Some(ConstantPoolEntry::String { utf8_index }) => {
            class.utf8_at(*utf8_index).ok().map(str::to_owned)
        }
        Some(ConstantPoolEntry::Class { name_index }) => {
            class.utf8_at(*name_index).ok().map(str::to_owned)
        }
        _ => None,
    }
}

fn independent_const_pairs(class: &ClassFile) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for method in &class.methods {
        for attribute in &method.attributes {
            let attribute: &Attribute = attribute;
            if class.utf8_at(attribute.name_index).ok() != Some("Code") {
                continue;
            }
            let code: CodeAttribute = parse_code_attribute(&attribute.info).expect("code");
            let insns: Vec<Instruction> = disassemble(&code.code).expect("disasm");
            for insn in &insns {
                let value: Option<String> = match &insn.operands {
                    Operands::Byte(v) | Operands::Short(v) => Some(v.to_string()),
                    Operands::ConstPool(index) if matches!(insn.opcode, 0x12..=0x14) => {
                        ldc_render(class, *index)
                    }
                    _ => None,
                };
                if let Some(value) = value {
                    pairs.push((insn.mnemonic.to_owned(), value));
                }
            }
        }
    }
    pairs.sort();
    pairs
}

fn const_carrier(mnemonic: &str) -> bool {
    matches!(mnemonic, "bipush" | "sipush" | "ldc" | "ldc_w" | "ldc2_w")
}

fn lifted_const_pairs(nir: &NirModule) -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && const_carrier(ins.mnemonic.as_str())
                && let Some(value) = ins.operands.first()
            {
                pairs.push((ins.mnemonic.clone(), value.clone()));
            }
        }
    }
    pairs.sort();
    pairs
}

#[test]
fn lifted_constants_match_the_independent_classfile_decode() {
    let class: ClassFile = parse_classfile(STRINGER).expect("parse StringerClassic.class");
    let oracle: Vec<(String, String)> = independent_const_pairs(&class);
    let nir: NirModule = lift_classfile(STRINGER).expect("lift StringerClassic.class");
    let lifted: Vec<(String, String)> = lifted_const_pairs(&nir);

    assert!(
        !oracle.is_empty(),
        "the fixture must carry inline constants that would fail a dropped-operand lift"
    );
    assert_eq!(
        lifted, oracle,
        "each lifted const must equal the value decoded straight from the class bytes"
    );
}

#[test]
fn string_and_numeric_constants_are_not_dropped() {
    let class: ClassFile = parse_classfile(STRINGER).expect("parse StringerClassic.class");
    let oracle: Vec<(String, String)> = independent_const_pairs(&class);

    let ldc_strings: usize = oracle
        .iter()
        .filter(|(name, value): &&(String, String)| name == "ldc" && value.parse::<i64>().is_err())
        .count();
    assert!(
        ldc_strings >= 5,
        "the fixture must load several string constants via ldc: {oracle:?}"
    );

    let nir: NirModule = lift_classfile(STRINGER).expect("lift StringerClassic.class");
    let values: BTreeSet<String> = lifted_const_pairs(&nir)
        .into_iter()
        .map(|(_, value): (String, String)| value)
        .collect();

    for expected in [
        "5381",
        "33",
        "63",
        "16777619",
        "2147483647",
        "com/disrobe/bench/StringerClassic",
    ] {
        assert!(
            values.contains(expected),
            "source declares the constant {expected}; lifted consts were {values:?}"
        );
    }
}
