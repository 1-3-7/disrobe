#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_py_deob::{PeelResult, peel};

fn script_path() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("tests")
        .join("layered_gate")
        .join("make_loaders.py")
}

struct Gate {
    _scratch: disrobe_core::scratch::ScratchDir,
    python: PathBuf,
    dir: PathBuf,
    artifacts: serde_json::Value,
}

fn build_gate(slot: &str) -> Gate {
    let python: PathBuf = common::require_python();
    let purpose: String = format!("disrobe_layered_gate_{slot}");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create gate directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    let output: std::process::Output = Command::new(&python)
        .arg(script_path())
        .arg("build")
        .arg(&dir)
        .output()
        .expect("run generator");
    assert!(
        output.status.success(),
        "generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let artifacts: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("generator emitted json");
    Gate {
        _scratch: scratch,
        python,
        dir,
        artifacts,
    }
}

fn artifact(gate: &Gate, name: &str) -> Vec<u8> {
    let path: &str = gate.artifacts[name]
        .as_str()
        .unwrap_or_else(|| panic!("artifact {name} missing"));
    std::fs::read(path).unwrap_or_else(|_| panic!("read artifact {name}"))
}

fn grade_equivalent(gate: &Gate, recovered_source: &str, label: &str) -> bool {
    let recovered_path: PathBuf = gate.dir.join(format!("recovered_{label}.py"));
    std::fs::write(&recovered_path, recovered_source).expect("write recovered source");
    let original_path: &str = gate.artifacts["app_source"].as_str().expect("app_source");
    let output: std::process::Output = Command::new(&gate.python)
        .arg(script_path())
        .arg("grade")
        .arg(original_path)
        .arg(&recovered_path)
        .output()
        .expect("run grader");
    let verdict: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or(serde_json::Value::Null);
    let equivalent: bool = verdict["equivalent"].as_bool().unwrap_or(false);
    if !equivalent {
        eprintln!(
            "grade {label}: not equivalent.\nstdout={}\nstderr={}\nrecovered:\n{recovered_source}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    equivalent
}

fn peel_artifact(gate: &Gate, name: &str) -> PeelResult {
    let bytes: Vec<u8> = artifact(gate, name);
    peel(&bytes).unwrap_or_else(|e| panic!("peel {name}: {e:?}"))
}

const RECOMPILE_EQUIVALENT_CASES: [&str; 9] = [
    "base64",
    "base64_zlib",
    "base85_zlib_marshal",
    "base32",
    "lzma_marshal",
    "bz2_marshal",
    "marshal_bare",
    "marshal_zlib",
    "xor1_base64_zlib_marshal",
];

#[test]
fn layered_chains_recover_to_recompile_equivalent_source() {
    let gate: Gate = build_gate("chains");
    let mut checked: usize = 0;
    for name in RECOMPILE_EQUIVALENT_CASES {
        let result: PeelResult = peel_artifact(&gate, name);
        assert!(
            result.recovered,
            "{name}: engine did not recover, steps={:?}, wall={:?}",
            result.steps, result.wall
        );
        assert!(
            grade_equivalent(&gate, &result.final_source, name),
            "{name}: recovered source not recompile-equivalent to the original"
        );
        checked += 1;
    }
    assert_eq!(checked, RECOMPILE_EQUIVALENT_CASES.len());
}

#[test]
fn keyed_loaders_recover_keys_and_source() {
    let gate: Gate = build_gate("keyed");
    let multi: PeelResult = peel_artifact(&gate, "xor_multi_lzma_marshal_loader");
    assert!(
        multi.recovered,
        "xor_multi: not recovered, steps={:?}",
        multi.steps
    );
    assert!(
        multi
            .key_findings
            .iter()
            .any(|k| k.key_hex == "73656b726574"),
        "xor_multi: expected sibling key 'sekret' recovered, got {:?}",
        multi.key_findings
    );
    assert!(
        grade_equivalent(&gate, &multi.final_source, "xor_multi_lzma_marshal"),
        "xor_multi: recovered source not recompile-equivalent"
    );

    let rc4: PeelResult = peel_artifact(&gate, "rc4_zlib_marshal_loader");
    assert!(rc4.recovered, "rc4: not recovered, steps={:?}", rc4.steps);
    assert!(
        rc4.key_findings
            .iter()
            .any(|k| k.key_hex == "7263347365637265746b6579"),
        "rc4: expected sibling rc4 key 'rc4secretkey' recovered, got {:?}",
        rc4.key_findings
    );
    assert!(
        grade_equivalent(&gate, &rc4.final_source, "rc4_zlib_marshal"),
        "rc4: recovered source not recompile-equivalent"
    );
}

#[test]
fn single_byte_xor_recovered_key_is_load_bearing() {
    let gate: Gate = build_gate("single");
    let result: PeelResult = peel_artifact(&gate, "xor1_base64_zlib_marshal");
    assert!(
        result.recovered,
        "xor1: not recovered, steps={:?}",
        result.steps
    );
    assert!(
        result.key_findings.iter().any(|k| k.key_hex == "5e"),
        "xor1: expected single-byte key 0x5e recovered, got {:?}",
        result.key_findings
    );
}

const CODEC_SCHEME_CASES: [&str; 5] = [
    "base91_zlib_marshal",
    "base45_zlib_marshal",
    "ascii85_zlib_marshal",
    "percent_zlib_marshal",
    "base91_source",
];

#[test]
fn core_codec_schemes_recover_to_recompile_equivalent_source() {
    let gate: Gate = build_gate("codec");
    let mut checked: usize = 0;
    for name in CODEC_SCHEME_CASES {
        let result: PeelResult = peel_artifact(&gate, name);
        assert!(
            result.recovered,
            "{name}: engine did not recover, steps={:?}, wall={:?}",
            result.steps, result.wall
        );
        assert!(
            result.steps.iter().any(|s| s.decoder.contains("codec:")),
            "{name}: expected a codec step, got {:?}",
            result.steps
        );
        assert!(
            grade_equivalent(&gate, &result.final_source, name),
            "{name}: recovered source not recompile-equivalent to the original"
        );
        checked += 1;
    }
    assert_eq!(checked, CODEC_SCHEME_CASES.len());
}

struct CipherCase {
    artifact: &'static str,
    decoder_marker: &'static str,
    key_hex: &'static str,
}

const CIPHER_CASES: [CipherCase; 5] = [
    CipherCase {
        artifact: "tea_zlib_marshal_loader",
        decoder_marker: "tea:",
        key_hex: "7465612d3136627974652d6b65792121",
    },
    CipherCase {
        artifact: "xtea_zlib_marshal_loader",
        decoder_marker: "xtea:",
        key_hex: "787465612d6b65792d7369787465656e",
    },
    CipherCase {
        artifact: "xxtea_zlib_marshal_loader",
        decoder_marker: "xxtea:",
        key_hex: "78787465612d6b65792d313662797465",
    },
    CipherCase {
        artifact: "chacha20_zlib_marshal_loader",
        decoder_marker: "chacha20:",
        key_hex: "63686163686132302d3235366269742d6b65792d7468697274792d74776f2121",
    },
    CipherCase {
        artifact: "salsa20_zlib_marshal_loader",
        decoder_marker: "salsa20:",
        key_hex: "73616c736132302d3235366269742d6b65792d7468697274792d74776f212121",
    },
];

#[test]
fn new_cipher_loaders_recover_keys_and_recompile_equivalent_source() {
    let gate: Gate = build_gate("ciphers");
    let mut checked: usize = 0;
    for case in CIPHER_CASES {
        let result: PeelResult = peel_artifact(&gate, case.artifact);
        assert!(
            result.recovered,
            "{a}: engine did not recover, steps={:?}, wall={:?}",
            result.steps,
            result.wall,
            a = case.artifact
        );
        assert!(
            result
                .steps
                .iter()
                .any(|s| s.decoder.contains(case.decoder_marker)),
            "{a}: expected a {m} cipher step, got {:?}",
            result.steps,
            a = case.artifact,
            m = case.decoder_marker
        );
        assert!(
            result
                .key_findings
                .iter()
                .any(|k| k.key_hex == case.key_hex),
            "{a}: expected recovered key {k}, got {:?}",
            result.key_findings,
            a = case.artifact,
            k = case.key_hex
        );
        assert!(
            grade_equivalent(&gate, &result.final_source, case.artifact),
            "{a}: recovered source not recompile-equivalent to the original",
            a = case.artifact
        );
        checked += 1;
    }
    assert_eq!(checked, CIPHER_CASES.len());
}
