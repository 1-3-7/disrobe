#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, NameRecoveryStats,
    SourceMap, attach_sourcemap_names, extract_signatures, lift_function_body, parse_source_map,
};
use wasmparser::{FunctionBody, Parser, Payload};

const NAMED_ADD: &str = r#"
(module
  (func $add (export "add") (param i32 i32) (result i32)
    (local i32)
    local.get 0
    local.get 1
    i32.add
    local.set 2
    local.get 2))
"#;

fn lift_named(wasm: &[u8], sig: &FunctionSig, target: LiftTarget) -> LiftResult {
    let callees: CalleeNames = CalleeNames::new(Vec::new());
    for payload in Parser::new(0).parse_all(wasm) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            let body: FunctionBody<'_> = body;
            return lift_function_body(&body, sig, &callees, target);
        }
    }
    panic!("no code section");
}

#[test]
fn positional_names_without_debug_info() {
    let wasm: Vec<u8> = wat::parse_str(NAMED_ADD).expect("wat");
    let sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    let add: &FunctionSig = sigs.defined_sig(0).expect("add sig");
    let lifted: LiftResult = lift_named(&wasm, add, LiftTarget::Rust);
    assert!(
        lifted.pseudo_source.contains("p0: i32, p1: i32"),
        "no debug info -> positional params, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        lifted.pseudo_source.contains("let mut l2:"),
        "no debug info -> positional local l2, got:\n{}",
        lifted.pseudo_source
    );
}

#[test]
fn dwarf_style_names_emitted_in_lifted_rust() {
    let wasm: Vec<u8> = wat::parse_str(NAMED_ADD).expect("wat");
    let mut sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    let attached: usize = sigs.attach_local_names(|defined_index: u32| {
        if defined_index == 0 {
            vec![
                Some("lhs".to_owned()),
                Some("rhs".to_owned()),
                Some("acc".to_owned()),
            ]
        } else {
            Vec::new()
        }
    });
    assert_eq!(attached, 1, "exactly one function received names");

    let add: &FunctionSig = sigs.defined_sig(0).expect("add sig");
    let lifted: LiftResult = lift_named(&wasm, add, LiftTarget::Rust);
    assert!(
        lifted
            .pseudo_source
            .contains("pub fn add(lhs: i32, rhs: i32)"),
        "real param names, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        lifted.pseudo_source.contains("let mut acc:"),
        "real local name, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        lifted.pseudo_source.contains("wasm_i32_add(lhs, rhs)"),
        "names used at the operator site, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        !lifted.pseudo_source.contains("p0")
            && !lifted.pseudo_source.contains("p1")
            && !lifted.pseudo_source.contains("l2"),
        "no positional names leak when debug info is present:\n{}",
        lifted.pseudo_source
    );
}

#[test]
fn sourcemap_names_drive_the_lifter() {
    let wasm: Vec<u8> = wat::parse_str(NAMED_ADD).expect("wat");
    let mut sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    let json: &str = r#"{
        "version": 3,
        "sources": ["add.rs"],
        "names": ["lhs", "rhs", "acc"],
        "mappings": "AAAAA,IAAAC,IAAAC"
    }"#;
    let map: SourceMap = parse_source_map(json.as_bytes()).expect("map");
    let stats: NameRecoveryStats = attach_sourcemap_names(&mut sigs, &map, |defined_index: u32| {
        if defined_index == 0 {
            Some((0, 4096))
        } else {
            None
        }
    });
    assert_eq!(stats.functions_with_names, 1);

    let add: &FunctionSig = sigs.defined_sig(0).expect("add sig");
    let lifted: LiftResult = lift_named(&wasm, add, LiftTarget::TypeScript);
    assert!(
        lifted
            .pseudo_source
            .contains("export function add(lhs: number, rhs: number)"),
        "source-map names in typescript output, got:\n{}",
        lifted.pseudo_source
    );
}

#[test]
fn reserved_word_local_name_is_escaped() {
    let wasm: Vec<u8> = wat::parse_str(NAMED_ADD).expect("wat");
    let mut sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    sigs.attach_local_names(|defined_index: u32| {
        if defined_index == 0 {
            vec![Some("type".to_owned()), Some("match".to_owned()), None]
        } else {
            Vec::new()
        }
    });
    let add: &FunctionSig = sigs.defined_sig(0).expect("add sig");
    let lifted: LiftResult = lift_named(&wasm, add, LiftTarget::Rust);
    assert!(
        lifted.pseudo_source.contains("_type") && lifted.pseudo_source.contains("_match"),
        "reserved words escaped with leading underscore, got:\n{}",
        lifted.pseudo_source
    );
    let reparsed: Result<Vec<u8>, _> = wat::parse_str(NAMED_ADD);
    assert!(reparsed.is_ok());
}

fn name_map(entries: &[(u8, &str)]) -> Vec<u8> {
    let mut v: Vec<u8> = vec![u8::try_from(entries.len()).expect("entry count fits u8")];
    for (idx, name) in entries {
        v.push(*idx);
        v.push(u8::try_from(name.len()).expect("name len fits u8"));
        v.extend_from_slice(name.as_bytes());
    }
    v
}

fn append_local_name_section(module: &mut Vec<u8>, func_index: u8, locals: &[(u8, &str)]) {
    let inner: Vec<u8> = name_map(locals);
    let mut indirect: Vec<u8> = vec![1u8, func_index];
    indirect.extend_from_slice(&inner);
    let mut local_sub: Vec<u8> = vec![
        2u8,
        u8::try_from(indirect.len()).expect("indirect len fits u8"),
    ];
    local_sub.extend_from_slice(&indirect);
    let mut payload: Vec<u8> = vec![4u8];
    payload.extend_from_slice(b"name");
    payload.extend_from_slice(&local_sub);
    module.push(0u8);
    module.push(u8::try_from(payload.len()).expect("name payload fits u8"));
    module.extend_from_slice(&payload);
}

#[test]
fn wasm_name_section_local_names_drive_the_lifter() {
    let mut wasm: Vec<u8> = wat::parse_str(
        "(module (func (export \"compute\") (param i32) (result i32) (local i32) local.get 0))",
    )
    .expect("wat");
    append_local_name_section(&mut wasm, 0, &[(0, "counter"), (1, "scratch")]);

    let sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    let compute: &FunctionSig = sigs.defined_sig(0).expect("compute sig");
    assert_eq!(
        compute.local_name(0),
        Some("counter"),
        "param name recovered from the wasm name section"
    );
    assert_eq!(
        compute.local_name(1),
        Some("scratch"),
        "local name recovered from the wasm name section"
    );

    let lifted: LiftResult = lift_named(&wasm, compute, LiftTarget::Rust);
    assert!(
        lifted
            .pseudo_source
            .contains("pub fn compute(counter: i32)"),
        "name-section param name used in the signature, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        lifted.pseudo_source.contains("let mut scratch:"),
        "name-section local name used in the declaration, got:\n{}",
        lifted.pseudo_source
    );
    assert!(
        !lifted.pseudo_source.contains("p0") && !lifted.pseudo_source.contains("l1"),
        "no positional names leak when the name section carries local names:\n{}",
        lifted.pseudo_source
    );
}

#[test]
fn dwarf_names_override_wasm_name_section_locals() {
    let mut wasm: Vec<u8> = wat::parse_str(
        "(module (func (export \"compute\") (param i32) (result i32) (local i32) local.get 0))",
    )
    .expect("wat");
    append_local_name_section(&mut wasm, 0, &[(0, "from_name_sec"), (1, "also_name_sec")]);
    let mut sigs: ModuleSignatures = extract_signatures(&wasm).expect("sigs");
    assert_eq!(
        sigs.defined_sig(0).and_then(|s| s.local_name(0)),
        Some("from_name_sec")
    );

    let attached: usize = sigs.attach_local_names(|defined_index: u32| {
        if defined_index == 0 {
            vec![
                Some("dwarf_param".to_owned()),
                Some("dwarf_local".to_owned()),
            ]
        } else {
            Vec::new()
        }
    });
    assert_eq!(attached, 1);
    let compute: &FunctionSig = sigs.defined_sig(0).expect("compute sig");
    assert_eq!(
        compute.local_name(0),
        Some("dwarf_param"),
        "richer debug-info names take precedence over the name section"
    );
}
