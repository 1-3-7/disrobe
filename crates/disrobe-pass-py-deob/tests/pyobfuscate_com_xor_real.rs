#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_py_deob::obfuscators::pyobfuscate_com_xor::PyobfuscateComXorPass;
use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome, Quality};
use disrobe_pass_py_deob::{AutoDeobOutcome, ObfuscatorPass, RouteKind, auto_deobfuscate};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy)]
struct PinnedCapture {
    slot: &'static str,
    sha256: &'static str,
    exit_code: i32,
    stdout: &'static str,
}

const HELLO: PinnedCapture = PinnedCapture {
    slot: "hello",
    sha256: "e7ffaed3f3a84dc1662906c06efabc2786b106747f602d1941ac81cd85375c4b",
    exit_code: 0,
    stdout: "hello world\n",
};

const SAMPLE: PinnedCapture = PinnedCapture {
    slot: "sample",
    sha256: "920e7edbb66bdceb974dd2828b2713ef2ce8cab77d5d21ccd6b3be6af857217b",
    exit_code: 0,
    stdout: "240\n",
};

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

fn assert_is_the_pinned_capture(fixture: &[u8], pinned: &PinnedCapture) {
    assert_eq!(
        format!("{:x}", Sha256::digest(fixture)),
        pinned.sha256,
        "corpus/python/obfuscators/pyobfuscate_com/real_{}.py is not the capture whose plain \
         program's exit code and stdout this test pins; corpus/python/obfuscators/MANIFEST.toml \
         records the pinned digest",
        pinned.slot
    );
}

fn assert_obfuscation_gone(slot: &str, quality: Quality, recovered: &str) {
    assert_eq!(
        quality,
        Quality::Full,
        "the {slot} recovery must fold every lambda-XOR idiom before anything runs it; a partial \
         recovery still carries pyobfuscate.com output:\n{recovered}"
    );
    let residual: DetectReport = PyobfuscateComXorPass.detect(recovered.as_bytes());
    assert!(
        !residual.matched,
        "the {slot} recovery still matches the pyobfuscate.com detector ({:?}):\n{recovered}",
        residual.markers
    );
}

#[test]
#[should_panic(expected = "the hello recovery still matches the pyobfuscate.com detector")]
fn a_recovery_that_hands_back_its_input_is_refused_before_python_runs() {
    assert_obfuscation_gone(
        HELLO.slot,
        Quality::Full,
        include_str!("../../../corpus/python/obfuscators/pyobfuscate_com/real_hello.py"),
    );
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

fn behaves_as_pinned(python: &str, recovered: &str, pinned: &PinnedCapture) -> (bool, String) {
    let scratch: disrobe_core::scratch::ScratchDir = gate_dir(pinned.slot);
    let dir: PathBuf = scratch.path().to_path_buf();
    let recovered_path: PathBuf = dir.join(format!("recovered_{}.py", pinned.slot));
    let expected_path: PathBuf = dir.join(format!("expected_{}.txt", pinned.slot));
    std::fs::write(&recovered_path, recovered).expect("write recovered");
    std::fs::write(&expected_path, pinned.stdout).expect("write pinned stdout");
    let output: std::process::Output = Command::new(python)
        .arg(oracle_script())
        .arg("equivalent")
        .arg(&recovered_path)
        .arg(pinned.exit_code.to_string())
        .arg(&expected_path)
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
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", HELLO.slot)
    else {
        common::skip_absent_corpus(
            "real_hello_detects_and_recovers_exec_equivalent",
            "pyobfuscate_com",
        );
        return;
    };
    assert_is_the_pinned_capture(&fixture, &HELLO);
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
    assert_obfuscation_gone(HELLO.slot, outcome.quality, &outcome.recovered_source);

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

    let Some(python): Option<String> = python_exe() else {
        eprintln!(
            "skip: python interpreter absent; recovery produced:\n{}",
            outcome.recovered_source
        );
        return;
    };
    assert!(
        reparses(&python, &outcome.recovered_source, HELLO.slot),
        "recovered source must re-parse as Python:\n{}",
        outcome.recovered_source
    );
    let (equivalent, detail): (bool, String) =
        behaves_as_pinned(&python, &outcome.recovered_source, &HELLO);
    assert!(
        equivalent,
        "recovered source must exit and print exactly as the plain program does; {detail}\n\
         recovered:\n{}",
        outcome.recovered_source
    );
    let mutated: String = format!("{}\nprint('mutation-kill')\n", outcome.recovered_source);
    let (mutant_equivalent, mutant_detail): (bool, String) =
        behaves_as_pinned(&python, &mutated, &HELLO);
    assert!(
        !mutant_equivalent && mutant_detail.contains("verdict=MISMATCH"),
        "the pinned-stdout oracle must reject a recovery that prints one extra line; \
         {mutant_detail}"
    );
}

#[test]
fn real_sample_detects_and_recovers_reparseable() {
    let Some(fixture): Option<Vec<u8>> = common::load_real_fixture("pyobfuscate_com", SAMPLE.slot)
    else {
        common::skip_absent_corpus(
            "real_sample_detects_and_recovers_reparseable",
            "pyobfuscate_com",
        );
        return;
    };
    assert_is_the_pinned_capture(&fixture, &SAMPLE);
    let detect: DetectReport = PyobfuscateComXorPass.detect(&fixture);
    assert!(
        detect.matched,
        "new XOR/lambda pass must detect the real pyobfuscate.com 2026 sample; markers={:?}",
        detect.markers
    );
    let outcome: PeelOutcome = PyobfuscateComXorPass.peel(&fixture).expect("peel sample");
    assert_ne!(outcome.recovered_source.as_bytes(), fixture.as_slice());
    assert_obfuscation_gone(SAMPLE.slot, outcome.quality, &outcome.recovered_source);

    let Some(python): Option<String> = python_exe() else {
        eprintln!(
            "skip: python interpreter absent; recovery produced:\n{}",
            outcome.recovered_source
        );
        return;
    };
    assert!(
        reparses(&python, &outcome.recovered_source, SAMPLE.slot),
        "recovered sample must re-parse as Python:\n{}",
        outcome.recovered_source
    );
    let (equivalent, detail): (bool, String) =
        behaves_as_pinned(&python, &outcome.recovered_source, &SAMPLE);
    assert!(
        equivalent,
        "recovered sample must exit and print exactly as the plain program does; {detail}\n\
         recovered:\n{}",
        outcome.recovered_source
    );
}
