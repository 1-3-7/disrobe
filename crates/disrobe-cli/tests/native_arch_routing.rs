#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use serde_json::Value;

const ARM32: &str = "corpus/native/arch/arm32_forms.elf";
const AARCH64: &str = "corpus/native/discovery/disc_aarch64.unstripped.elf";

const ARM32_FUNCTIONS: u64 = 4;
const ARM32_NAMES: [&str; 4] = ["acc", "pick", "chain", "_start"];
const ARM32_REGISTERS: [&str; 3] = ["r0", "lr", "pc"];
const AARCH64_REGISTERS: [&str; 3] = ["x0", "x24", "x30"];

fn word_present(source: &str, needle: &str) -> bool {
    source
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|token: &str| token == needle)
}

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn cli_binary() -> PathBuf {
    let exe: PathBuf = std::env::current_exe().expect("current exe");
    let mut dir: PathBuf = exe.parent().expect("exe dir").to_path_buf();
    while dir
        .file_name()
        .and_then(|part: &std::ffi::OsStr| part.to_str())
        != Some("debug")
        && dir
            .file_name()
            .and_then(|part: &std::ffi::OsStr| part.to_str())
            != Some("release")
    {
        if !dir.pop() {
            break;
        }
    }
    dir.push(if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    });
    dir
}

fn decompile(relative: &str) -> (Value, String) {
    let binary: PathBuf = cli_binary();
    assert!(
        binary.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli --bin disrobe` first",
        binary.display()
    );
    let mut input: PathBuf = workspace_root();
    input.push(relative);
    assert!(
        input.exists(),
        "committed fixture missing at {}; this test grades a real compiled image and must not be skipped",
        input.display()
    );
    let scratch: ScratchDir = ScratchDir::create("native-arch-routing").expect("scratch dir");
    let out: PathBuf = scratch.path().join("decompiled");
    let output: Output = Command::new(&binary)
        .arg("native")
        .arg("decompile")
        .arg(&input)
        .arg("--out")
        .arg(&out)
        .env_remove("RUST_LOG")
        .output()
        .expect("native decompile must run");
    assert!(
        output.status.success(),
        "native decompile {relative} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest_path: PathBuf = out.join("manifest.json");
    let manifest: String = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("manifest at {}: {e}", manifest_path.display()));
    let manifest: Value = serde_json::from_str(&manifest).expect("manifest is json");
    let source_path: PathBuf = PathBuf::from(
        manifest["source"]
            .as_str()
            .expect("the manifest names its emitted source"),
    );
    let source: String = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|e| panic!("emitted source at {}: {e}", source_path.display()));
    (manifest, source)
}

#[test]
fn a_real_arm32_image_reaches_pseudo_source_instead_of_being_refused() {
    let (manifest, source): (Value, String) = decompile(ARM32);
    assert_eq!(manifest["architecture"], "arm32");
    assert_eq!(manifest["backend"], "native-in-tree-arm32");
    assert_eq!(
        manifest["functions_total"].as_u64(),
        Some(ARM32_FUNCTIONS),
        "the arm32 image declares four functions"
    );
    assert_eq!(
        manifest["functions_recovered"].as_u64(),
        Some(ARM32_FUNCTIONS),
        "every arm32 function must reach pseudo-source"
    );
    let recovered: Vec<&str> = manifest["recovered"]
        .as_array()
        .expect("recovered is an array")
        .iter()
        .map(|entry: &Value| {
            entry["name"]
                .as_str()
                .expect("every recovered entry is named")
        })
        .collect();
    for name in ARM32_NAMES {
        assert!(
            recovered.contains(&name),
            "arm32 recovery lost {name}; recovered {recovered:?}"
        );
        assert!(
            source.contains(name),
            "the emitted source has no body for {name}"
        );
    }
}

#[test]
fn arm32_bytes_are_decoded_by_the_arm32_decoder_and_not_another() {
    let (_, source): (Value, String) = decompile(ARM32);
    for register in ARM32_REGISTERS {
        assert!(
            word_present(&source, register),
            "the recovered arm32 source never names the arm register {register}, so these bytes were not decoded as arm32"
        );
    }
    for register in AARCH64_REGISTERS {
        assert!(
            !word_present(&source, register),
            "the recovered arm32 source names the aarch64 register {register}, so an aarch64 decoder read these arm32 bytes"
        );
    }
}

#[test]
fn every_arm32_function_is_attributed_to_the_engine_that_produced_it() {
    let (manifest, _): (Value, String) = decompile(ARM32);
    let engines: Vec<&str> = manifest["recovered"]
        .as_array()
        .expect("recovered is an array")
        .iter()
        .map(|entry: &Value| {
            entry["engine"]
                .as_str()
                .expect("every recovered entry names its engine")
        })
        .collect();
    assert_eq!(engines.len() as u64, ARM32_FUNCTIONS);
    for engine in &engines {
        assert_eq!(
            *engine, "nir",
            "arm32 has no whole-program or image-leaf engine, so every function must come from the p-code lift; saw {engines:?}"
        );
    }
}

#[test]
fn aarch64_keeps_its_whole_program_engine_after_the_shared_routing() {
    let (manifest, _): (Value, String) = decompile(AARCH64);
    assert_eq!(manifest["architecture"], "aarch64");
    assert_eq!(manifest["backend"], "native-in-tree-aarch64");
    let whole_program: u64 = manifest["functions_whole_program"]
        .as_u64()
        .expect("the manifest counts whole-program recoveries");
    assert!(
        whole_program > 0,
        "aarch64 must still reach its whole-program engine through the shared path, saw {whole_program}"
    );
    let recovered: u64 = manifest["functions_recovered"]
        .as_u64()
        .expect("the manifest counts recoveries");
    assert!(
        recovered >= whole_program,
        "whole-program recoveries cannot exceed total recoveries"
    );
}
