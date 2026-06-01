#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_pickle::{
    Disassembly, PickleValue, SafetyReport, Severity, VmTrace, analyze_safety, disassemble,
    execute, to_python,
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
    let Ok(entries) = std::fs::read_dir(dir) else {
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
    let Some(root): Option<PathBuf> = corpus_root() else {
        eprintln!("corpus/pickle not present; run generate.py - skipping");
        return;
    };
    let mut files: Vec<PathBuf> = Vec::new();
    collect_pkl(&root, &mut files);
    if files.is_empty() {
        eprintln!("skip: no .pkl fixtures under {root:?} - run generate.py");
        return;
    }

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
    let Some(root): Option<PathBuf> = corpus_root() else {
        return;
    };
    for proto in 0u8..=5 {
        let path: PathBuf = root
            .join("benign")
            .join(format!("p{proto}"))
            .join("int.pkl");
        if !path.is_file() {
            continue;
        }
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
    let Some(root): Option<PathBuf> = corpus_root() else {
        return;
    };
    let path: PathBuf = root.join("benign").join("p4").join("nested_dict.pkl");
    if !path.is_file() {
        return;
    }
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let trace: VmTrace = execute(&disassemble(&bytes).expect("disasm")).expect("vm");
    assert!(matches!(trace.result, PickleValue::Dict(_)));
}

#[test]
fn disasm_matches_pickletools_reference() {
    let Some(root): Option<PathBuf> = corpus_root() else {
        return;
    };
    let ref_path: PathBuf = root.join("opcode_ref.json");
    let Ok(ref_text): std::io::Result<String> = std::fs::read_to_string(&ref_path) else {
        eprintln!("opcode_ref.json absent - skipping differential disasm check");
        return;
    };
    let reference: std::collections::BTreeMap<String, Vec<String>> =
        serde_json::from_str(&ref_text).expect("parse opcode_ref.json");
    assert!(
        !reference.is_empty(),
        "opcode_ref.json carries no fixture sequences"
    );

    let mut checked: usize = 0;
    for (rel, expected) in &reference {
        let path: PathBuf = root.join(rel);
        if !path.is_file() {
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read fixture");
        let dis: Disassembly = disassemble(&bytes).unwrap_or_else(|e| panic!("disasm {rel}: {e}"));
        let actual: Vec<String> = dis.instructions.iter().map(|i| i.name.clone()).collect();
        assert_eq!(
            &actual, expected,
            "opcode stream for {rel} diverges from CPython pickletools reference"
        );
        checked += 1;
    }
    if checked == 0 {
        eprintln!("skip: no .pkl reference fixtures present to differential-check");
    }
}
