#![allow(clippy::expect_used, clippy::panic)]

use disrobe_pass_jvm::bytecode::{
    CodeAttribute, Instruction, Operands, disassemble, parse_code_attribute,
};
use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::parse_classfile;

const EDGE_CASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const CHAIN_VALUE_JVM_LOCAL: u16 = 0;
const PALINDROME_I_JVM_LOCAL: u16 = 4;
const PALINDROME_J_JVM_LOCAL: u16 = 1;
const FACTORIAL_N_JVM_LOCAL: u16 = 0;
const FACTORIAL_N_MINUS_ONE_JVM_LOCAL: u16 = 1;
const REVERSE_N_JVM_LOCAL: u16 = 1;
const REVERSE_I_JVM_LOCAL: u16 = 3;
const REVERSE_N_MINUS_ONE_MINUS_I_JVM_LOCAL: u16 = 4;

fn edge_cases_class() -> ClassFile {
    let translated: Dex2JarResult =
        translate_dex_bytes(EDGE_CASES_DEX).expect("translate EdgeCases.dex");
    let bytes: Vec<u8> = translated
        .jar_entries
        .into_iter()
        .find_map(|(name, bytes): (String, Vec<u8>)| (name == "EdgeCases.class").then_some(bytes))
        .expect("translated EdgeCases.class");
    parse_classfile(&bytes).expect("parse translated EdgeCases.class")
}

fn method_code(class: &ClassFile, name: &str, descriptor: &str) -> CodeAttribute {
    let method: &MethodInfo = class
        .methods
        .iter()
        .find(|method: &&MethodInfo| {
            class.utf8_at(method.name_index).ok() == Some(name)
                && class.utf8_at(method.descriptor_index).ok() == Some(descriptor)
        })
        .unwrap_or_else(|| panic!("translated method {name}{descriptor}"));
    let attribute: &Attribute = method
        .attributes
        .iter()
        .find(|attribute: &&Attribute| class.utf8_at(attribute.name_index).ok() == Some("Code"))
        .unwrap_or_else(|| panic!("Code attribute for {name}{descriptor}"));
    parse_code_attribute(&attribute.info)
        .unwrap_or_else(|_| panic!("parse Code attribute for {name}{descriptor}"))
}

fn instructions(class: &ClassFile, name: &str, descriptor: &str) -> Vec<Instruction> {
    let code: CodeAttribute = method_code(class, name, descriptor);
    disassemble(&code.code).unwrap_or_else(|_| panic!("disassemble {name}{descriptor}"))
}

fn int_local_index(instruction: &Instruction, mnemonic: &str) -> Option<u16> {
    match (mnemonic, instruction.mnemonic, &instruction.operands) {
        ("iload", "iload", Operands::Local(index))
        | ("istore", "istore", Operands::Local(index)) => Some(*index),
        ("iload", "iload_0", _) | ("istore", "istore_0", _) => Some(0),
        ("iload", "iload_1", _) | ("istore", "istore_1", _) => Some(1),
        ("iload", "iload_2", _) | ("istore", "istore_2", _) => Some(2),
        ("iload", "iload_3", _) | ("istore", "istore_3", _) => Some(3),
        _ => None,
    }
}

fn semantic_mnemonics(instructions: &[Instruction]) -> Vec<&'static str> {
    instructions
        .iter()
        .map(|instruction: &Instruction| instruction.mnemonic)
        .filter(|mnemonic: &&str| {
            !mnemonic.ends_with("load")
                && !mnemonic.contains("load_")
                && !mnemonic.ends_with("store")
                && !mnemonic.contains("store_")
                && !matches!(
                    *mnemonic,
                    "nop"
                        | "dup"
                        | "dup_x1"
                        | "dup_x2"
                        | "dup2"
                        | "dup2_x1"
                        | "dup2_x2"
                        | "swap"
                        | "pop"
                        | "pop2"
                )
        })
        .collect()
}

#[test]
fn tracked_increment_sites_preserve_statement_and_expression_shapes() {
    let class: ClassFile = edge_cases_class();
    let expression: Vec<Instruction> = instructions(
        &class,
        "lambda$chain$1",
        "(Ljava/lang/Integer;)Ljava/lang/Integer;",
    );
    assert_eq!(
        expression
            .iter()
            .filter(|instruction: &&Instruction| instruction.mnemonic == "iadd")
            .count(),
        1
    );
    assert!(
        expression
            .iter()
            .all(|instruction: &Instruction| instruction.mnemonic != "iinc")
    );
    assert!(
        expression.windows(4).any(|window: &[Instruction]| {
            int_local_index(&window[0], "iload") == Some(CHAIN_VALUE_JVM_LOCAL)
                && window[1].mnemonic == "iconst_1"
                && window[2].mnemonic == "iadd"
                && int_local_index(&window[3], "istore") == Some(CHAIN_VALUE_JVM_LOCAL)
        }),
        "{expression:#?}"
    );

    let statements: Vec<Instruction> =
        instructions(&class, "isPalindrome", "(Ljava/lang/String;)Z");
    let sites: Vec<(u16, i32)> = statements
        .iter()
        .filter_map(|instruction: &Instruction| match instruction.operands {
            Operands::Iinc { index, delta } => Some((index, delta)),
            _ => None,
        })
        .collect();
    let deltas: Vec<i32> = statements
        .iter()
        .filter_map(|instruction: &Instruction| match instruction.operands {
            Operands::Iinc { delta, .. } => Some(delta),
            _ => None,
        })
        .collect();
    assert_eq!(deltas, vec![1, -1]);
    assert_eq!(
        sites,
        vec![(PALINDROME_I_JVM_LOCAL, 1), (PALINDROME_J_JVM_LOCAL, -1),]
    );
}

#[test]
fn tracked_negative_literals_preserve_subtraction_order() {
    let class: ClassFile = edge_cases_class();
    let factorial: Vec<Instruction> = instructions(&class, "recursiveFactorial", "(I)I");
    let factorial_mnemonics: Vec<&str> = semantic_mnemonics(&factorial);
    assert!(
        factorial_mnemonics
            .windows(2)
            .any(|window: &[&str]| window == ["iconst_1", "isub"])
    );
    assert!(!factorial_mnemonics.contains(&"iadd"));
    assert!(
        factorial.windows(4).any(|window: &[Instruction]| {
            int_local_index(&window[0], "iload") == Some(FACTORIAL_N_JVM_LOCAL)
                && window[1].mnemonic == "iconst_1"
                && window[2].mnemonic == "isub"
                && int_local_index(&window[3], "istore") == Some(FACTORIAL_N_MINUS_ONE_JVM_LOCAL)
        }),
        "{factorial:#?}"
    );

    let reverse: Vec<Instruction> = instructions(&class, "reverseArray", "([I)[I");
    let reverse_mnemonics: Vec<&str> = semantic_mnemonics(&reverse);
    assert!(
        reverse_mnemonics
            .windows(2)
            .any(|window: &[&str]| window == ["iconst_1", "isub"])
    );
    assert_eq!(
        reverse_mnemonics
            .iter()
            .filter(|mnemonic: &&&str| **mnemonic == "isub")
            .count(),
        2
    );
    assert!(
        reverse.windows(8).any(|window: &[Instruction]| {
            int_local_index(&window[0], "iload") == Some(REVERSE_N_JVM_LOCAL)
                && window[1].mnemonic == "iconst_1"
                && window[2].mnemonic == "isub"
                && int_local_index(&window[3], "istore")
                    == Some(REVERSE_N_MINUS_ONE_MINUS_I_JVM_LOCAL)
                && int_local_index(&window[4], "iload")
                    == Some(REVERSE_N_MINUS_ONE_MINUS_I_JVM_LOCAL)
                && int_local_index(&window[5], "iload") == Some(REVERSE_I_JVM_LOCAL)
                && window[6].mnemonic == "isub"
                && int_local_index(&window[7], "istore")
                    == Some(REVERSE_N_MINUS_ONE_MINUS_I_JVM_LOCAL)
        }),
        "{reverse:#?}"
    );
}

#[test]
fn tracked_loop_constants_preserve_odd_branch_arithmetic() {
    let class: ClassFile = edge_cases_class();
    for (name, descriptor) in [
        ("collatzPath", "(I)Ljava/lang/String;"),
        ("hailstone", "(I)I"),
    ] {
        let method: Vec<Instruction> = instructions(&class, name, descriptor);
        let mnemonics: Vec<&str> = semantic_mnemonics(&method);
        assert!(
            mnemonics
                .windows(4)
                .any(|window: &[&str]| window == ["iconst_3", "imul", "iconst_1", "iadd"]),
            "translated {name}{descriptor} omitted the proven loop constant"
        );
    }
}
