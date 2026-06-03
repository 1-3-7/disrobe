#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use disrobe_pass_jvm::{
    ClassDataItem, CodeItem, DexClass, DexFile, EncodedMethod, disassemble_dalvik, parse_dex,
    parse_dex_code_item, walk_dex_classes,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");

fn code_items(bytes: &[u8]) -> Vec<CodeItem> {
    let dex: DexFile = parse_dex(bytes).expect("parse dex");
    let classes: Vec<DexClass> = walk_dex_classes(bytes, &dex).expect("walk classes");
    let mut out: Vec<CodeItem> = Vec::new();
    for class in &classes {
        let Some(data): Option<&ClassDataItem> = class.class_data.as_ref() else {
            continue;
        };
        for method in data.methods() {
            let m: &EncodedMethod = method;
            if m.code_off == 0 {
                continue;
            }
            out.push(parse_dex_code_item(bytes, m.code_off as usize).expect("code_item"));
        }
    }
    out
}

fn emit_method_smali(units: &[u16]) -> String {
    let decoded: Vec<(u32, &'static str)> = disassemble_dalvik(units);
    let mut body: String = String::with_capacity(decoded.len() * 24);
    let _ = writeln!(body, ".method <recovered>()V");
    for (offset, mnemonic) in &decoded {
        let _ = writeln!(body, "    {offset:#06x}: {mnemonic}");
    }
    let _ = writeln!(body, ".end method");
    body
}

#[test]
fn disassembles_real_dex_method_to_concrete_mnemonics() {
    assert_eq!(&HELLO_DEX[..4], b"dex\n", "fixture is a real DEX");
    let items: Vec<CodeItem> = code_items(HELLO_DEX);
    assert!(
        !items.is_empty(),
        "library walker reached at least one code_item"
    );

    let mut all_mnemonics: BTreeSet<&'static str> = BTreeSet::new();
    let mut richest_body: String = String::new();
    let mut richest_len: usize = 0;
    for code in &items {
        if code.insns.len() > richest_len {
            richest_len = code.insns.len();
            richest_body = emit_method_smali(&code.insns);
        }
        for (_off, mnemonic) in disassemble_dalvik(&code.insns) {
            all_mnemonics.insert(mnemonic);
        }
    }

    assert!(
        richest_body.contains(".method") && richest_body.contains(".end method"),
        "emitted a real smali method shell"
    );
    for expected in [
        "new-instance",
        "const-string",
        "invoke-direct",
        "invoke-virtual",
        "sget-object",
        "move-result-object",
        "return-void",
    ] {
        assert!(
            all_mnemonics.contains(expected),
            "in-house decoder recovered `{expected}` from real Hello.dex; got {all_mnemonics:?}"
        );
    }
    assert!(
        all_mnemonics.contains("return-object") || all_mnemonics.contains("return"),
        "recovered a return-family opcode"
    );
    assert!(
        all_mnemonics.len() >= 8,
        "recovered a non-trivial instruction vocabulary, got {}",
        all_mnemonics.len()
    );
}

#[test]
fn smallest_real_method_is_init_invoke_direct_return_void() {
    let items: Vec<CodeItem> = code_items(HELLO_DEX);
    let init: &CodeItem = items
        .iter()
        .find(|c| c.insns.len() == 4)
        .expect("Greeter.<init> code_item with 4 units");
    let decoded: Vec<&'static str> = disassemble_dalvik(&init.insns)
        .into_iter()
        .map(|(_, m)| m)
        .collect();
    assert_eq!(
        decoded,
        vec!["invoke-direct", "return-void"],
        "real <init> decodes exactly to invoke-direct/return-void"
    );
}
