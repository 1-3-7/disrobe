#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{
    CodeItem, DEX_ENDIAN_TAG, DalvikFormat, DecodedInsn, DexClass, DexFile, DexHeader, DexVersion,
    EncodedMethod, IndexKind, MethodId, decode_dalvik, parse_dex, parse_dex_code_item,
    parse_dex_header, walk_dex_classes,
};

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");
const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_KT_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCasesKt.dex");

const ALL_DEX: [(&str, &[u8]); 3] = [
    ("Hello.dex", HELLO_DEX),
    ("EdgeCases.dex", EDGECASES_DEX),
    ("EdgeCasesKt.dex", EDGECASES_KT_DEX),
];

#[test]
fn parses_real_hello_dex_from_d8() {
    assert_eq!(&HELLO_DEX[..4], b"dex\n");
    assert_eq!(&HELLO_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(HELLO_DEX).expect("parse hello.dex");
    assert!(matches!(h.version, DexVersion::V035));
    let endian: u32 =
        u32::from_le_bytes([HELLO_DEX[40], HELLO_DEX[41], HELLO_DEX[42], HELLO_DEX[43]]);
    assert_eq!(endian, DEX_ENDIAN_TAG);
}

#[test]
fn parses_real_edgecases_dex_from_d8() {
    assert_eq!(&EDGECASES_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_DEX[4..7], b"035");
    let h: DexHeader = parse_dex_header(EDGECASES_DEX).expect("parse edgecases.dex");
    assert!(matches!(h.version, DexVersion::V035));
    assert!(
        EDGECASES_DEX.len() > 10_000,
        "expected non-trivial dex size"
    );
}

#[test]
fn parses_real_kotlin_dex_v039_for_min_api_33() {
    assert_eq!(&EDGECASES_KT_DEX[..4], b"dex\n");
    assert_eq!(&EDGECASES_KT_DEX[4..7], b"039");
    let h: DexHeader = parse_dex_header(EDGECASES_KT_DEX).expect("parse kotlin dex");
    assert!(matches!(h.version, DexVersion::V039));
    assert!(
        EDGECASES_KT_DEX.len() > 50_000,
        "expected substantial kotlin dex"
    );
}

fn code_items(bytes: &[u8]) -> Vec<(EncodedMethod, CodeItem)> {
    let dex: DexFile = parse_dex(bytes).expect("parse dex");
    let classes: Vec<DexClass> = walk_dex_classes(bytes, &dex).expect("walk classes");
    let mut out: Vec<(EncodedMethod, CodeItem)> = Vec::new();
    for class in &classes {
        let Some(data): Option<&disrobe_pass_jvm::ClassDataItem> = class.class_data.as_ref() else {
            continue;
        };
        for method in data.methods() {
            if method.code_off == 0 {
                continue;
            }
            let code: CodeItem =
                parse_dex_code_item(bytes, method.code_off as usize).expect("parse code_item");
            out.push((*method, code));
        }
    }
    out
}

#[test]
fn library_walker_finds_greeter_init_invoke_direct_return_void() {
    let methods: Vec<(EncodedMethod, CodeItem)> = code_items(HELLO_DEX);
    let init: &(EncodedMethod, CodeItem) = methods
        .iter()
        .find(|(_, c)| c.insns.len() == 4)
        .expect("Greeter.<init> code_item of 4 units");
    let decoded: Vec<&'static str> = decode_dalvik(&init.1.insns)
        .into_iter()
        .map(|d: DecodedInsn| d.mnemonic)
        .collect();
    assert_eq!(
        decoded,
        vec!["invoke-direct", "return-void"],
        "real Greeter.<init> decodes exactly to invoke-direct/return-void"
    );
}

#[test]
fn edgecases_class_data_offsets_resolve_in_bounds() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse edgecases.dex");
    let classes: Vec<DexClass> = walk_dex_classes(EDGECASES_DEX, &dex).expect("walk");
    let mut resolvable_code_offsets: usize = 0;
    for class in &classes {
        if let Some(data) = class.class_data.as_ref() {
            for method in data.methods() {
                if method.code_off != 0 {
                    parse_dex_code_item(EDGECASES_DEX, method.code_off as usize)
                        .expect("code_off resolves in-bounds");
                    resolvable_code_offsets += 1;
                }
            }
        }
    }
    assert!(
        resolvable_code_offsets >= 80,
        "expected >=80 code offsets to resolve in-bounds, got {resolvable_code_offsets}"
    );
}

#[test]
fn every_code_item_resyncs_across_all_real_dex() {
    let mut total_methods: usize = 0;
    for (name, bytes) in ALL_DEX {
        for (method, code) in code_items(bytes) {
            let decoded: Vec<DecodedInsn> = decode_dalvik(&code.insns);
            let consumed: usize = decoded.iter().map(|d| usize::from(d.width).max(1)).sum();
            assert_eq!(
                consumed,
                code.insns.len(),
                "{name} method_idx {} desynced: consumed {consumed} of {} units",
                method.method_idx,
                code.insns.len()
            );
            for insn in &decoded {
                assert_ne!(
                    insn.format,
                    DalvikFormat::FUnused,
                    "{name} method_idx {} hit unused opcode 0x{:02X}",
                    method.method_idx,
                    insn.opcode
                );
            }
            total_methods += 1;
        }
    }
    assert!(
        total_methods > 700,
        "expected to re-sync 700+ real methods, got {total_methods}"
    );
}

#[test]
fn const_string_indices_point_into_string_table() {
    for (name, bytes) in ALL_DEX {
        let dex: DexFile = parse_dex(bytes).expect("parse");
        let mut checked: usize = 0;
        for (_method, code) in code_items(bytes) {
            for insn in decode_dalvik(&code.insns) {
                if insn.index_kind == IndexKind::String {
                    let idx: usize = string_index(&insn);
                    assert!(
                        idx < dex.strings.len(),
                        "{name}: const-string idx {idx} out of string table ({} entries)",
                        dex.strings.len()
                    );
                    checked += 1;
                }
            }
        }
        if name == "Hello.dex" {
            assert!(
                checked > 0,
                "Hello.dex must contain at least one const-string"
            );
        }
    }
}

fn string_index(insn: &DecodedInsn) -> usize {
    use disrobe_pass_jvm::DalvikOperands;
    match insn.operands {
        DalvikOperands::RegAIndex { index, .. } => index as usize,
        _ => panic!("const-string should carry RegAIndex operands"),
    }
}

#[test]
fn invoke_direct_init_resolves_to_object_init_in_hello() {
    use disrobe_pass_jvm::DalvikOperands;
    let dex: DexFile = parse_dex(HELLO_DEX).expect("parse hello");
    let methods: Vec<(EncodedMethod, CodeItem)> = code_items(HELLO_DEX);
    let init: &(EncodedMethod, CodeItem) = methods
        .iter()
        .find(|(_, c)| c.insns.len() == 4)
        .expect("init code item");
    let first: DecodedInsn = decode_dalvik(&init.1.insns)
        .into_iter()
        .next()
        .expect("first insn");
    assert_eq!(first.mnemonic, "invoke-direct");
    assert_eq!(first.index_kind, IndexKind::Method);
    let DalvikOperands::Invoke { index, .. } = first.operands else {
        panic!("invoke-direct must carry Invoke operands");
    };
    let target: &MethodId = dex
        .method_ids
        .get(index as usize)
        .expect("method idx in range");
    assert_eq!(target.class, "Ljava/lang/Object;");
    assert_eq!(target.name, "<init>");
    assert_eq!(target.proto.return_type, "V");
    assert!(
        target.proto.parameters.is_empty(),
        "Object.<init> takes no parameters"
    );
}

#[test]
fn no_panic_fallthrough_on_any_real_opcode() {
    for (_name, bytes) in ALL_DEX {
        for (_method, code) in code_items(bytes) {
            let _decoded: Vec<DecodedInsn> = decode_dalvik(&code.insns);
        }
    }
}
