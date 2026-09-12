#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_py_deob::obfuscators::pyobfuscate_com_xor::PyobfuscateComXorPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};
use disrobe_pass_py_deob::{AutoDeobOutcome, ObfuscatorPass, RouteKind, auto_deobfuscate};

fn python_exe() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        let probe: std::io::Result<std::process::Output> =
            Command::new(candidate).arg("--version").output();
        if let Ok(out) = probe
            && out.status.success()
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn oracle_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("pyobfuscate_xor_gate")
        .join("oracle.py")
}

fn gate_dir(slot: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe_pyobf_xor_{slot}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create gate directory")
}

fn reparses(python: &str, source: &str, slot: &str) -> bool {
    let scratch: disrobe_core::scratch::ScratchDir = gate_dir(slot);
    let dir: PathBuf = scratch.path().to_path_buf();
    let path: PathBuf = dir.join(format!("recovered_{slot}.py"));
    std::fs::write(&path, source).expect("write recovered");
    let output: std::process::Output = Command::new(python)
        .arg(oracle_script())
        .arg("reparse")
        .arg(&path)
        .output()
        .expect("run oracle reparse");
    String::from_utf8_lossy(&output.stdout).trim() == "OK"
}

fn exec_equivalent(python: &str, original: &[u8], recovered: &str, slot: &str) -> (bool, String) {
    let scratch: disrobe_core::scratch::ScratchDir = gate_dir(slot);
    let dir: PathBuf = scratch.path().to_path_buf();
    let original_path: PathBuf = dir.join(format!("original_{slot}.py"));
    let recovered_path: PathBuf = dir.join(format!("recovered_{slot}.py"));
    std::fs::write(&original_path, original).expect("write original");
    std::fs::write(&recovered_path, recovered).expect("write recovered");
    let output: std::process::Output = Command::new(python)
        .arg(oracle_script())
        .arg("equivalent")
        .arg(&original_path)
        .arg(&recovered_path)
        .output()
        .expect("run oracle equivalent");
    let verdict: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    (
        verdict == "EQUIVALENT",
        format!("verdict={verdict} stderr={stderr}"),
    )
}

#[test]
fn real_hello_detects_and_recovers_exec_equivalent() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", "hello")
    else {
        common::skip_absent_corpus(
            "real_hello_detects_and_recovers_exec_equivalent",
            "pyobfuscate_com",
        );
        return;
    };
    let detect: DetectReport = PyobfuscateComXorPass.detect(&fixture);
    assert!(
        detect.matched,
        "new XOR/lambda pass must detect the real pyobfuscate.com 2026 hello fixture; markers={:?}",
        detect.markers
    );
    let outcome: PeelOutcome = PyobfuscateComXorPass.peel(&fixture).expect("peel hello");
    assert_ne!(
        outcome.recovered_source.as_bytes(),
        fixture.as_slice(),
        "peel must transform the input"
    );

    let Some(python): Option<String> = python_exe() else {
        eprintln!(
            "skip: python interpreter absent; recovery produced:\n{}",
            outcome.recovered_source
        );
        return;
    };
    assert!(
        reparses(&python, &outcome.recovered_source, "hello"),
        "recovered source must re-parse as Python:\n{}",
        outcome.recovered_source
    );
    let (equivalent, detail): (bool, String) =
        exec_equivalent(&python, &fixture, &outcome.recovered_source, "hello");
    assert!(
        equivalent,
        "recovered source must be exec-equivalent to the original; {detail}\nrecovered:\n{}",
        outcome.recovered_source
    );
    assert_eq!(
        outcome.quality,
        Quality::Full,
        "fully folded + canonicalized hello should grade Full"
    );

    let routed: AutoDeobOutcome = auto_deobfuscate(&fixture, None);
    assert_eq!(
        routed.kind,
        RouteKind::Deobfuscated,
        "auto route must deobfuscate the XOR/lambda hello fixture"
    );
    assert_eq!(
        routed.peel.and_then(|p| p.obfuscator).map(|o| o.obfuscator),
        Some(Obfuscator::PyobfuscateComXor),
        "auto route must select the dedicated XOR/lambda pass"
    );
}

#[test]
fn real_sample_detects_and_recovers_reparseable() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", "sample")
    else {
        common::skip_absent_corpus(
            "real_sample_detects_and_recovers_reparseable",
            "pyobfuscate_com",
        );
        return;
    };
    let detect: DetectReport = PyobfuscateComXorPass.detect(&fixture);
    assert!(
        detect.matched,
        "new XOR/lambda pass must detect the real pyobfuscate.com 2026 sample; markers={:?}",
        detect.markers
    );
    let outcome: PeelOutcome = PyobfuscateComXorPass.peel(&fixture).expect("peel sample");
    assert_ne!(outcome.recovered_source.as_bytes(), fixture.as_slice());

    let Some(python): Option<String> = python_exe() else {
        eprintln!(
            "skip: python interpreter absent; recovery produced:\n{}",
            outcome.recovered_source
        );
        return;
    };
    assert!(
        reparses(&python, &outcome.recovered_source, "sample"),
        "recovered sample must re-parse as Python:\n{}",
        outcome.recovered_source
    );
    let (equivalent, detail): (bool, String) =
        exec_equivalent(&python, &fixture, &outcome.recovered_source, "sample");
    assert!(
        equivalent,
        "recovered sample must be exec-equivalent to the original; {detail}\nrecovered:\n{}",
        outcome.recovered_source
    );
}
