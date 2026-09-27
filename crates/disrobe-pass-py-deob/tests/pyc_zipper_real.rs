#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_deob::obfuscators::{DetectReport, Obfuscator, PeelOutcome};
use disrobe_pass_py_deob::{
    ObfuscatorPass, PycZipperPass, RouteKind, auto_deobfuscate, recover_pyc_zipper,
};

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("pyc_zipper")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = corpus_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "the tracked pyc-zipper fixture {} is unreadable ({e}); restore it with git checkout",
            path.display()
        )
    })
}

const DIS_ORACLE: &str = r"
import sys, marshal, dis, io, re

ADDR = re.compile(r' at 0x[0-9A-Fa-f]+')

def code_of(pyc_path):
    raw = open(pyc_path, 'rb').read()
    header = 16 if raw[16] in (0x63, 0xe3, 0xc3) else 12
    return marshal.loads(raw[header:])

def listing(co):
    out = io.StringIO()
    dis.dis(co, file=out)
    return ADDR.sub(' at 0x', out.getvalue())

recovered = code_of(sys.argv[1])
original = code_of(sys.argv[2])
if listing(recovered) == listing(original):
    print('BYTECODE_EQUIVALENT')
else:
    print('MISMATCH')
";

fn assert_bytecode_equivalent(python: &Path, recovered_pyc: &[u8], original_name: &str) {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_pycz").expect("scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recovered_path: PathBuf = dir.join("recovered.pyc");
    let oracle_path: PathBuf = dir.join("oracle.py");
    std::fs::write(&recovered_path, recovered_pyc).expect("write recovered");
    std::fs::write(&oracle_path, DIS_ORACLE).expect("write oracle");
    let original_path: PathBuf = corpus_dir().join(original_name);

    let output: std::process::Output = Command::new(python)
        .arg(&oracle_path)
        .arg(&recovered_path)
        .arg(&original_path)
        .output()
        .expect("run dis oracle");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "dis oracle failed: {stdout}\n{stderr}"
    );
    assert!(
        stdout.trim() == "BYTECODE_EQUIVALENT",
        "recovered code object is not bytecode-equivalent to the original-compiled {original_name}: {stdout}\n{stderr}"
    );
}

fn detect_and_peel(slot: &str, expected: &str) -> PeelOutcome {
    let fixture: Vec<u8> = read_fixture(slot);
    let detect: DetectReport = PycZipperPass.detect(&fixture);
    assert_eq!(detect.obfuscator, Obfuscator::PycZipper);
    assert!(detect.matched, "pyc-zipper {slot} not detected: {detect:?}");
    assert!(
        detect
            .markers
            .iter()
            .any(|m: &String| m == &format!("{expected}-decompress")),
        "expected {expected} marker: {detect:?}"
    );
    let outcome: PeelOutcome = PycZipperPass
        .peel(&fixture)
        .unwrap_or_else(|e| panic!("pyc-zipper {slot} peel failed: {e:?}"));
    assert_eq!(
        outcome.diagnostics.get("compressor").map(String::as_str),
        Some(expected),
        "compressor diagnostic mismatch for {slot}"
    );
    outcome
}

#[test]
fn detects_and_peels_zlib_bz2_lzma() {
    let mut recovered: Vec<(&str, String)> = Vec::new();
    for (slot, comp) in [
        ("sample_zlib.pyc", "zlib"),
        ("sample_bz2.pyc", "bz2"),
        ("sample_lzma.pyc", "lzma"),
    ] {
        let outcome: PeelOutcome = detect_and_peel(slot, comp);
        assert_eq!(
            outcome.stages_applied,
            vec![
                "pyc-header".to_owned(),
                "marshal".to_owned(),
                comp.to_owned(),
                "marshal".to_owned(),
                "decompile".to_owned(),
            ],
            "stage chain mismatch for {slot}"
        );
        assert!(
            !outcome.recovered_source.trim().is_empty(),
            "empty recovery for {slot}"
        );
        recovered.push((slot, outcome.recovered_source));
    }
    let (first_slot, first_source): &(&str, String) = &recovered[0];
    for (slot, source) in &recovered[1..] {
        assert_eq!(
            source, first_source,
            "{slot} and {first_slot} wrap one compiled module, so they must decompile identically"
        );
    }
}

#[test]
fn recovered_source_contains_original_symbols() {
    let outcome: PeelOutcome = detect_and_peel("sample_zlib.pyc", "zlib");
    let src: &str = &outcome.recovered_source;
    for needle in ["greet", "main", "hello, ", "total chars:"] {
        assert!(
            src.contains(needle),
            "recovered source missing {needle}:\n{src}"
        );
    }
}

#[test]
fn clean_pyc_and_garbage_are_not_claimed() {
    let clean: Vec<u8> = read_fixture("sample_orig.pyc");
    assert!(
        !PycZipperPass.detect(&clean).matched,
        "an unpacked pyc must not be flagged as pyc-zipper"
    );
    assert!(
        PycZipperPass.peel(&clean).is_err(),
        "clean pyc must not peel"
    );
    let garbage: &[u8] = &[0u8, 1, 2, 3, 0xff, 0xfe, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0];
    assert!(!PycZipperPass.detect(garbage).matched);
    assert!(PycZipperPass.peel(garbage).is_err());

    let source_packer: &[u8] =
        b"import zlib, marshal\nexec(marshal.loads(zlib.decompress(b'x')))\n";
    assert!(
        !PycZipperPass.detect(source_packer).matched,
        "a text source packer belongs to the pypacker pass, not pyc-zipper"
    );
}

#[test]
fn auto_route_recognizes_pyc_zipper() {
    let fixture: Vec<u8> = read_fixture("sample_zlib.pyc");
    let route = auto_deobfuscate(&fixture, None);
    assert_eq!(
        route.kind,
        RouteKind::Deobfuscated,
        "auto route did not deobfuscate"
    );
    let chain: String = route.chain.join(" | ");
    assert!(
        chain.contains("PycZipper"),
        "auto route chain missing PycZipper: {chain}"
    );
}

#[test]
fn recovered_bytecode_is_equivalent_to_original_under_cpython_314() {
    let python: PathBuf = common::require_python_314();
    for slot in ["sample_zlib.pyc", "sample_bz2.pyc", "sample_lzma.pyc"] {
        let fixture: Vec<u8> = read_fixture(slot);
        let recovered_pyc: Vec<u8> = recover_pyc_zipper(&fixture)
            .unwrap_or_else(|e| panic!("recover_pyc for {slot} failed: {e:?}"));
        assert_bytecode_equivalent(&python, &recovered_pyc, "sample_orig.pyc");
    }
}
