#![allow(clippy::panic)]

use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

use disrobe_pass_pyarmor::{
    BccPublication, UnpackOptions, link_bcc_from_unpack, publish_bcc_recovery,
    unpack_wrapper_text_with_options,
};

mod common;

use common::{Run, run_disrobe, temp_dir};

const BCC_WRAPPER: &str = "corpus/python/pyarmor/v9-bcc/default/known_plaintext.py";
const BCC_WRAPPER_SHA256: &str = "b71480d70250997ea96bc3d3d5331d028e8ac657cca9a7dc3fdfdea8f52bb2cf";
const BCC_RUNTIME: &str =
    "corpus/python/pyarmor/v9-bcc/default/pyarmor_runtime_015009/pyarmor_runtime.pyd";
const BCC_RUNTIME_SHA256: &str = "105c97b2dcbdd1a0fc025f7f1c9c8317c0af113531f9d311d7e17cc010ccad9a";
const README_BCC_SAFETY: &str = "Only the PyArmor v6/v7 dynamic hook executes sample code, behind `--allow-dynamic` with a watchdog. `--allow-bcc` permits only in-tree static analysis and does not execute the sample or invoke external tools.";

fn workspace_root() -> Result<PathBuf, Box<dyn Error>> {
    let crate_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crates_dir: &Path = crate_dir
        .parent()
        .ok_or("CLI crate must be inside the crates directory")?;
    let root: &Path = crates_dir
        .parent()
        .ok_or("crates directory must be inside the workspace")?;
    if !root.join("Cargo.lock").is_file() {
        return Err("workspace root must contain Cargo.lock".into());
    }
    Ok(root.to_path_buf())
}

fn sha256_hex(path: &Path) -> Result<String, Box<dyn Error>> {
    use sha2::Digest as _;
    use std::fmt::Write as _;

    let bytes: Vec<u8> = std::fs::read(path)?;
    let digest: sha2::digest::Output<sha2::Sha256> = sha2::Sha256::digest(bytes);
    let mut encoded: String = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok(encoded)
}

fn output_inventory(root: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut files: BTreeSet<String> = BTreeSet::new();
    for entry_result in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry: walkdir::DirEntry = entry_result?;
        if !entry.file_type().is_file() {
            continue;
        }
        let relative: &Path = entry.path().strip_prefix(root)?;
        let name: String = relative.to_string_lossy().replace('\\', "/");
        files.insert(name);
    }
    Ok(files)
}

fn expected_inventory(manifest: &serde_json::Value) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut files: BTreeSet<String> = [
        "emit_ast.json",
        "emit_cfg.json",
        "emit_disasm.json",
        "emit_imports.json",
        "emit_ir.json",
        "emit_report.json",
        "emit_signatures.json",
        "emit_sourcemap.json",
        "emit_source.json",
        "emit_strings.json",
        "emit_symbols.json",
        "bcc/bcc-pseudo-c.c",
        "bcc/bcc-recovered.py",
        "bcc/bcc-recovery.json",
        "manifest.json",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let plaintext_size: u64 = manifest["plaintext_size"]
        .as_u64()
        .ok_or("manifest plaintext_size must be an integer")?;
    if plaintext_size > 0 {
        files.insert("payload.bin".to_owned());
    }
    let pyc_emitted: bool = manifest["pyc_emitted"]
        .as_bool()
        .ok_or("manifest pyc_emitted must be a boolean")?;
    if pyc_emitted {
        files.insert("known_plaintext.pyc".to_owned());
    }
    Ok(files)
}

fn grade_inventory(root: &Path, manifest: &serde_json::Value) -> Result<(), String> {
    let actual: BTreeSet<String> = output_inventory(root)
        .map_err(|error: Box<dyn Error>| format!("cannot inventory BCC CLI output: {error}"))?;
    let expected: BTreeSet<String> =
        expected_inventory(manifest).map_err(|error: Box<dyn Error>| {
            format!("cannot establish expected BCC CLI output: {error}")
        })?;
    if actual != expected {
        return Err(format!(
            "BCC CLI output inventory differs: actual={actual:?} expected={expected:?}"
        ));
    }
    Ok(())
}

#[test]
fn pyarmor_bcc_cli_and_auto_publish_the_canonical_recovery_bundle() -> Result<(), Box<dyn Error>> {
    let root: PathBuf = workspace_root()?;
    let input: PathBuf = root.join(BCC_WRAPPER);
    let runtime: PathBuf = root.join(BCC_RUNTIME);
    assert!(input.is_file(), "tracked BCC wrapper is missing");
    assert!(runtime.is_file(), "tracked BCC runtime is missing");
    assert_eq!(std::fs::metadata(&input)?.len(), 16_242);
    assert_eq!(sha256_hex(&input)?, BCC_WRAPPER_SHA256);
    let runtime_bytes: Vec<u8> = std::fs::read(&runtime)?;
    assert_eq!(&runtime_bytes[..2], b"MZ", "BCC runtime must be a PE image");
    assert_eq!(runtime_bytes.len(), 639_488, "BCC runtime size drifted");
    assert_eq!(
        sha256_hex(&runtime)?,
        BCC_RUNTIME_SHA256,
        "BCC runtime identity drifted"
    );

    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("pyarmor-bcc-cli-surface");
    let out_dir: PathBuf = scratch.path().join("out");
    let input_text: String = input.to_string_lossy().into_owned();
    let out_text: String = out_dir.to_string_lossy().into_owned();
    let run: Run = run_disrobe(&[
        "pyarmor",
        "unpack",
        &input_text,
        "--allow-bcc",
        "--all-emits",
        "--out",
        &out_text,
    ]);
    assert_eq!(run.code, 0, "stdout={} stderr={}", run.stdout, run.stderr);

    let manifest_bytes: Vec<u8> = std::fs::read(out_dir.join("manifest.json"))?;
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes)?;
    assert_eq!(manifest["protection"], "Bcc");
    assert_eq!(manifest["pass_path"], "pure-static");
    assert_eq!(manifest["allow_bcc"], true);
    assert!(manifest["dynamic_hook"].is_null());
    assert_eq!(manifest["plaintext_size"], 1_265);
    assert_eq!(manifest["pyc_emitted"], true);
    let manifest_runtime: &str = manifest["runtime"]
        .as_str()
        .ok_or("manifest runtime must be a path")?;
    assert_eq!(
        std::fs::canonicalize(manifest_runtime)?,
        std::fs::canonicalize(&runtime)?,
        "CLI must consume the tracked sibling BCC runtime"
    );
    assert_eq!(
        manifest["bcc_publication"]["schema"],
        "disrobe.pyarmor.bcc.recovery/v1"
    );
    assert_eq!(manifest["bcc_publication"]["function_count"], 4);
    assert_eq!(manifest["bcc_publication"]["modeled_count"], 0);
    assert_eq!(manifest["bcc_publication"]["unmodeled_count"], 4);
    assert_eq!(manifest["bcc_publication"]["refused_blob_count"], 0);

    let wrapper_text: String = std::fs::read_to_string(&input)?;
    let options: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked = unpack_wrapper_text_with_options(&wrapper_text, &input, &options)?;
    let linked = link_bcc_from_unpack(&unpacked, &wrapper_text, &input)?;
    let canonical: BccPublication = publish_bcc_recovery(&unpacked, &linked)?;
    for expected in canonical.artifacts() {
        let actual: Vec<u8> = std::fs::read(out_dir.join(expected.relative_path))?;
        assert_eq!(
            actual, expected.bytes,
            "dedicated CLI drifted from pass-owned {}",
            expected.relative_path
        );
    }

    let source_bytes: Vec<u8> = std::fs::read(out_dir.join("emit_source.json"))?;
    let source_emit: serde_json::Value = serde_json::from_slice(&source_bytes)?;
    assert_eq!(source_emit["applicable"], false);
    assert_eq!(source_emit["error_code"], "DR-IR-NotApplicable");
    grade_inventory(&out_dir, &manifest)
        .map_err(|error: String| -> Box<dyn Error> { error.into() })?;

    let fabricated_map: PathBuf = out_dir.join("bcc_function_map.json");
    std::fs::write(&fabricated_map, b"{}")?;
    let mutation_failure: String = match grade_inventory(&out_dir, &manifest) {
        Err(error) => error,
        Ok(()) => return Err("a fabricated BCC function map passed the output inventory".into()),
    };
    assert!(
        mutation_failure.contains("bcc_function_map.json"),
        "mutation failure must name the fabricated artifact: {mutation_failure}"
    );

    let auto_out: PathBuf = scratch.path().join("auto-out");
    let auto_text: String = auto_out.to_string_lossy().into_owned();
    let auto_run: Run = run_disrobe(&["auto", &input_text, "--out", &auto_text]);
    assert_eq!(
        auto_run.code, 0,
        "stdout={} stderr={}",
        auto_run.stdout, auto_run.stderr
    );
    for expected in canonical.artifacts() {
        let actual: Vec<u8> =
            std::fs::read(auto_out.join("extracted").join(expected.relative_path))?;
        assert_eq!(
            actual, expected.bytes,
            "auto drifted from pass-owned {}",
            expected.relative_path
        );
    }

    let readme: String = std::fs::read_to_string(root.join("README.md"))?;
    assert!(
        readme.contains(README_BCC_SAFETY),
        "README must distinguish the static BCC opt-in from sample execution"
    );
    Ok(())
}
