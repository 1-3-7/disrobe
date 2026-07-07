#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};

use disrobe_pass_pickle::{
    CallKind, CallableRef, DecodedArg, Disassembly, PickleValue, SafetyReport, Severity, VmTrace,
    analyze_safety, disassemble, execute, to_python,
};

fn corpus_root() -> Option<PathBuf> {
    let root: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("pickle");
    root.is_dir().then_some(root)
}

fn collect_pkl(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries): std::io::Result<std::fs::ReadDir> = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_pkl(&path, out);
        } else if path.extension().is_some_and(|e| e == "pkl") {
            out.push(path);
        }
    }
}

#[test]
fn every_fixture_disassembles_and_traces() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pkl(&root, &mut files);
    assert!(!files.is_empty(), "no .pkl fixtures under {root:?}");
    assert!(
        files.iter().any(|f: &PathBuf| f
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("malicious"))),
        "malicious fixtures missing"
    );

    for file in &files {
        let bytes: Vec<u8> = std::fs::read(file).expect("read fixture");
        let dis: Disassembly =
            disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {file:?}: {e}"));
        assert!(dis.stop_offset.is_some(), "no STOP in {file:?}");
        let trace: VmTrace = execute(&dis).unwrap_or_else(|e| panic!("vm {file:?}: {e}"));
        let _src: String = to_python(&trace.result);
        let report: SafetyReport = analyze_safety(&trace);

        let is_malicious: bool = file
            .components()
            .any(|c| c.as_os_str() == std::ffi::OsStr::new("malicious"));
        if is_malicious {
            assert_eq!(
                report.severity,
                Severity::OvertlyMalicious,
                "malicious fixture {file:?} not flagged OvertlyMalicious"
            );
        } else {
            assert_ne!(
                report.severity,
                Severity::OvertlyMalicious,
                "benign fixture {file:?} false-positive OvertlyMalicious"
            );
        }
    }
}

#[test]
fn benign_int_fixtures_decode_to_int() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    for proto in 0u8..=5 {
        let path: PathBuf = root
            .join("benign")
            .join(format!("p{proto}"))
            .join("int.pkl");
        assert!(path.is_file(), "p{proto}/int.pkl missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read int fixture");
        let trace: VmTrace = execute(&disassemble(&bytes).expect("disasm")).expect("vm");
        assert_eq!(
            trace.result,
            PickleValue::Int(42),
            "proto {proto} int fixture mismatch"
        );
    }
}

#[test]
fn nested_dict_fixture_structure() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let path: PathBuf = root.join("benign").join("p4").join("nested_dict.pkl");
    assert!(path.is_file(), "p4/nested_dict.pkl missing");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let trace: VmTrace = execute(&disassemble(&bytes).expect("disasm")).expect("vm");
    assert!(matches!(trace.result, PickleValue::Dict(_)));
}

#[test]
fn disasm_matches_pickletools_reference() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let ref_path: PathBuf = root.join("opcode_ref.json");
    let ref_text: String = std::fs::read_to_string(&ref_path).expect("opcode_ref.json must exist");
    let reference: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(&ref_text).expect("parse opcode_ref.json");
    assert!(
        !reference.is_empty(),
        "opcode_ref.json carries no fixture sequences"
    );

    let mut checked: usize = 0;
    for (rel, expected) in &reference {
        let path: PathBuf = root.join(rel);
        assert!(path.is_file(), "ref fixture {rel} missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
        let dis: Disassembly = disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {rel}: {e}"));
        let actual: Vec<String> = dis.instructions.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            &actual, expected,
            "opcode stream for {rel} diverges from CPython pickletools reference"
        );
        checked += 1;
    }
    assert!(checked > 0, "no reference fixtures present");
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn canon_arg(name: &str, arg: &DecodedArg) -> Vec<String> {
    let mut out: Vec<String> = vec![name.to_string()];
    match arg {
        DecodedArg::None => out.push("none".into()),
        DecodedArg::Bool(b) => {
            out.push("int".into());
            out.push(if *b { "1" } else { "0" }.into());
        }
        DecodedArg::Int(v) => {
            out.push("int".into());
            out.push(v.to_string());
        }
        DecodedArg::BigInt(s) => {
            out.push("int".into());
            out.push(s.clone());
        }
        DecodedArg::Float(f) => {
            out.push("float".into());
            out.push(hex_lower(&f.to_be_bytes()));
        }
        DecodedArg::Str(s) => {
            out.push("str".into());
            out.push(s.clone());
        }
        DecodedArg::Bytes(b) => {
            out.push("bytes".into());
            out.push(hex_lower(b));
        }
        DecodedArg::GlobalPair { module, name } => {
            out.push("pair".into());
            out.push(module.clone());
            out.push(name.clone());
        }
    }
    out
}

#[test]
fn decoded_args_match_pickletools_reference() {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let ref_path: PathBuf = root.join("arg_ref.json");
    let ref_text: String = std::fs::read_to_string(&ref_path).expect("arg_ref.json must exist");
    let reference: std::collections::BTreeMap<String, Vec<Vec<String>>> =
        serde_json::from_str(&ref_text).expect("parse arg_ref.json");
    assert!(
        !reference.is_empty(),
        "arg_ref.json carries no fixture sequences"
    );

    let mut checked_args: usize = 0;
    for (rel, expected) in &reference {
        let path: PathBuf = root.join(rel);
        assert!(path.is_file(), "ref fixture {rel} missing");
        let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
        let dis: Disassembly = disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {rel}: {e}"));
        let actual: Vec<Vec<String>> = dis
            .instructions
            .iter()
            .map(|i| canon_arg(&i.name, &i.arg))
            .collect();
        assert_eq!(
            &actual, expected,
            "decoded argument stream for {rel} diverges from CPython pickletools reference"
        );
        checked_args += expected.len();
    }
    assert!(
        checked_args > 0,
        "no reference argument sequences present to grade"
    );
}

fn trace_fixture(rel: &str) -> VmTrace {
    let root: PathBuf = corpus_root().expect("corpus/pickle must be committed");
    let path: PathBuf = root.join(rel);
    assert!(path.is_file(), "{rel} missing");
    let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
    execute(&disassemble(&bytes).expect("disasm")).expect("vm")
}

#[test]
fn cyclic_list_fixture_surfaces_back_edge() {
    let trace: VmTrace = trace_fixture("structural/cyclic_list.pkl");
    assert!(trace.cyclic, "cyclic_list must be flagged cyclic");
    assert_eq!(
        trace.result,
        PickleValue::List(vec![PickleValue::MemoRef { key: 0 }]),
        "real CPython self-referential list must decode to a memo back-edge"
    );
}

#[test]
fn cyclic_dict_fixture_surfaces_back_edge() {
    let trace: VmTrace = trace_fixture("structural/cyclic_dict.pkl");
    assert!(trace.cyclic, "cyclic_dict must be flagged cyclic");
    let PickleValue::Dict(pairs) = &trace.result else {
        panic!("expected dict, got {:?}", trace.result);
    };
    assert_eq!(pairs.len(), 1);
    assert_eq!(pairs[0].0, PickleValue::Str("self".into()));
    assert_eq!(pairs[0].1, PickleValue::MemoRef { key: 0 });
}

#[test]
fn shared_ref_fixture_is_acyclic() {
    let trace: VmTrace = trace_fixture("structural/shared_ref.pkl");
    assert!(
        !trace.cyclic,
        "shared (non-cyclic) reference must not be flagged cyclic"
    );
    let PickleValue::List(items) = &trace.result else {
        panic!("expected list");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0], items[1],
        "both entries must alias the same memo slot, or pickle.loads's shared identity is lost"
    );
    assert!(
        matches!(items[0], PickleValue::MemoRef { .. }),
        "real CPython shares this list by identity (a single PUT, reused via GET); the recovered \
         graph must reference one memo slot from both call sites rather than deep-copy the value, \
         or the rebuilt object silently loses `rebuilt[0] is rebuilt[1]`"
    );
}

#[test]
fn oob_buffer_fixture_marks_out_of_band() {
    let trace: VmTrace = trace_fixture("structural/oob_buffer.pkl");
    assert_eq!(
        trace.oob_buffer_count, 1,
        "real protocol-5 oob fixture must register one out-of-band buffer"
    );
    let PickleValue::Reduce { callable, args } = &trace.result else {
        panic!("expected reduce, got {:?}", trace.result);
    };
    assert_eq!(
        callable.as_ref(),
        &PickleValue::Global {
            module: "builtins".into(),
            name: "bytes".into(),
        }
    );
    let PickleValue::Tuple(t) = args.as_ref() else {
        panic!("expected tuple args");
    };
    assert_eq!(
        t.as_slice(),
        &[PickleValue::OutOfBandBuffer { readonly: true }],
        "the bytes() arg is an out-of-band readonly buffer, not in-stream data"
    );
}

#[test]
fn ext1_fixture_pushes_extension_code() {
    let trace: VmTrace = trace_fixture("structural/ext1.pkl");
    assert_eq!(
        trace.result,
        PickleValue::Ext { code: 16 },
        "EXT1 must surface the registry code; target stays runtime-only"
    );
}

#[test]
fn oob_buffer_call_graph_links_bytes() {
    let trace: VmTrace = trace_fixture("structural/oob_buffer.pkl");
    assert_eq!(trace.call_graph.len(), 1);
    let site: &disrobe_pass_pickle::CallSite = &trace.call_graph[0];
    assert_eq!(site.kind, CallKind::Reduce);
    assert_eq!(
        site.callable,
        CallableRef::Global {
            module: "builtins".into(),
            name: "bytes".into(),
        }
    );
}
