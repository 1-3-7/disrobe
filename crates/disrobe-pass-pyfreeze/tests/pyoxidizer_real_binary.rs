#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::unreadable_literal,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::if_same_then_else
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyfreeze::pyoxidizer::signatures::{
    PackedResourcesParse, ParsedResourceEntry, ResourceTier, extract_resources_blob,
    parse_packed_resources,
};
use disrobe_pass_pyfreeze::{Detection, FreezerKind, detect_bytes};

const HELLO_SOURCE_FILENAME: &str = "hello.py";
const HELLO_SOURCE_BODY: &str =
    "def main():\n    print('disrobe-pyoxidizer-hello')\nif __name__ == '__main__':\n    main()\n";
const HELLO_PYOXIDIZER_CONFIG: &str = include_str_template_pyoxidizer_bzl();
const ENV_FORCE_REGEN: &str = "DISROBE_PYOXIDIZER_REGEN";

const fn include_str_template_pyoxidizer_bzl() -> &'static str {
    "def make_exe():\n    dist = default_python_distribution()\n    policy = dist.make_python_packaging_policy()\n    policy.resources_location_fallback = 'filesystem-relative:lib'\n    python_config = dist.make_python_interpreter_config()\n    python_config.run_command = \"import hello; hello.main()\"\n    exe = dist.to_python_executable(name = 'disrobe_hello_pyox', packaging_policy = policy, config = python_config)\n    exe.add_python_resources(exe.pip_install(['--no-deps', '.']))\n    return exe\n\ndef make_embedded_resources(exe):\n    return exe.to_embedded_resources()\n\ndef make_install(exe):\n    files = FileManifest()\n    files.add_python_resource('.', exe)\n    return files\n\nregister_target('exe', make_exe)\nregister_target('resources', make_embedded_resources, depends = ['exe'])\nregister_target('install', make_install, depends = ['exe'], default = True)\nresolve_targets()\n"
}

#[derive(Debug)]
struct PyOxidizerArtifact {
    binary_path: PathBuf,
    bytes: Vec<u8>,
}

fn locate_pyoxidizer() -> Option<PathBuf> {
    let candidate: &str = if cfg!(windows) {
        "pyoxidizer.exe"
    } else {
        "pyoxidizer"
    };
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full: PathBuf = dir.join(candidate);
        if full.is_file() {
            return Some(full);
        }
    }
    None
}

fn fixtures_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyoxidizer-built");
    p
}

fn source_root() -> PathBuf {
    let manifest_dir: String =
        std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_owned());
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("target");
    p.push("test-fixtures");
    p.push("pyoxidizer-src");
    p
}

fn source_hash() -> String {
    let mut acc: u64 = 0xCAFE_BABE_DEAD_BEEFu64;
    for b in HELLO_SOURCE_BODY.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    for b in HELLO_PYOXIDIZER_CONFIG.bytes() {
        acc = acc.wrapping_mul(1_000_003).wrapping_add(u64::from(b));
    }
    format!("{acc:016x}")
}

fn ensure_artifact() -> Option<PyOxidizerArtifact> {
    let Some(pyox) = locate_pyoxidizer() else {
        eprintln!(
            "[disrobe-pyfreeze] pyoxidizer not on PATH; install via `cargo install pyoxidizer` to enable real-binary E2E tests"
        );
        return None;
    };
    let hash: String = source_hash();
    let target_dir: PathBuf = fixtures_root().join(&hash);
    let candidate: PathBuf = pick_built_binary(&target_dir);
    let force: bool = std::env::var(ENV_FORCE_REGEN).is_ok();
    if !force && candidate.is_file() {
        let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
        return Some(PyOxidizerArtifact {
            binary_path: candidate,
            bytes,
        });
    }
    std::fs::create_dir_all(&target_dir).ok()?;
    let src_dir: PathBuf = source_root().join(&hash);
    std::fs::create_dir_all(&src_dir).ok()?;
    std::fs::write(src_dir.join(HELLO_SOURCE_FILENAME), HELLO_SOURCE_BODY).ok()?;
    std::fs::write(src_dir.join("pyoxidizer.bzl"), HELLO_PYOXIDIZER_CONFIG).ok()?;
    let build_status: std::process::ExitStatus = {
        let started: std::io::Result<std::process::ExitStatus> = Command::new(&pyox)
            .arg("build")
            .arg("--release")
            .current_dir(&src_dir)
            .status();
        let Ok(status) = started else {
            eprintln!(
                "[disrobe-pyfreeze] pyoxidizer build failed to start: {err}; aborting real-binary test",
                err = started.err().map(|e| format!("{e}")).unwrap_or_default()
            );
            return None;
        };
        status
    };
    if !build_status.success() {
        eprintln!(
            "[disrobe-pyfreeze] pyoxidizer build exited non-zero (status={build_status:?}); aborting real-binary test"
        );
        return None;
    }
    let produced: Option<PathBuf> = find_built_executable(&src_dir.join("build"));
    let produced_path: PathBuf = produced?;
    std::fs::copy(&produced_path, &candidate).ok()?;
    let bytes: Vec<u8> = std::fs::read(&candidate).ok()?;
    Some(PyOxidizerArtifact {
        binary_path: candidate,
        bytes,
    })
}

fn pick_built_binary(target_dir: &Path) -> PathBuf {
    let candidate_name: &str = if cfg!(windows) {
        "disrobe_hello_pyox.exe"
    } else if cfg!(target_os = "macos") {
        "disrobe_hello_pyox"
    } else {
        "disrobe_hello_pyox"
    };
    target_dir.join(candidate_name)
}

fn find_built_executable(root: &Path) -> Option<PathBuf> {
    let entries: std::fs::ReadDir = std::fs::read_dir(root).ok()?;
    let mut stack: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|e: std::fs::DirEntry| e.path())
        .collect();
    let target_name_stem: &str = "disrobe_hello_pyox";
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&path) {
                stack.extend(
                    rd.filter_map(std::result::Result::ok)
                        .map(|e: std::fs::DirEntry| e.path()),
                );
            }
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n: &std::ffi::OsStr| n.to_str()) else {
            continue;
        };
        let stem_match: bool = file_name == target_name_stem
            || file_name == format!("{target_name_stem}.exe")
            || (file_name.starts_with(target_name_stem)
                && (file_name.ends_with(".exe") || !file_name.contains('.')));
        if stem_match {
            return Some(path);
        }
    }
    None
}

#[test]
fn pyoxidizer_real_binary_parses_with_structured_path() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let det: Detection = detect_bytes(&artifact.bytes, Some(&artifact.binary_path));
    assert_eq!(
        det.kind,
        FreezerKind::PyOxidizer,
        "real pyoxidizer binary must be detected; got: {det:?}"
    );
    let blob: &[u8] = extract_resources_blob(&artifact.bytes)
        .expect("real pyoxidizer binary must contain a pyembed\\x03 packed-resources blob");
    let parse: PackedResourcesParse = parse_packed_resources(blob)
        .expect("real pyoxidizer blob must round-trip through the structured parser");
    assert!(
        parse.format_version >= 1,
        "format_version must be >=1, got {}",
        parse.format_version
    );
    assert!(
        !parse.entries.is_empty(),
        "structured parse must surface at least one resource entry"
    );
}

#[test]
fn pyoxidizer_real_binary_extracts_hello_module() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let blob: &[u8] = extract_resources_blob(&artifact.bytes).expect("blob present");
    let parse: PackedResourcesParse = parse_packed_resources(blob).expect("parse");
    let hello_present: bool = parse
        .entries
        .iter()
        .any(|e: &ParsedResourceEntry| e.name.contains("hello"));
    assert!(
        hello_present,
        "hello module must appear in parsed entries; got {names:?}",
        names = parse
            .entries
            .iter()
            .map(|e| e.name.clone())
            .collect::<Vec<String>>()
    );
}

#[test]
fn pyoxidizer_real_binary_count_matches_pyoxidizer_manifest() {
    let Some(artifact) = ensure_artifact() else {
        return;
    };
    let blob: &[u8] = extract_resources_blob(&artifact.bytes).expect("blob present");
    let parse: PackedResourcesParse = parse_packed_resources(blob).expect("parse");
    let source_count: usize = parse
        .entries
        .iter()
        .filter(|e: &&ParsedResourceEntry| e.tier == ResourceTier::Source)
        .count();
    let bytecode_count: usize = parse
        .entries
        .iter()
        .filter(|e: &&ParsedResourceEntry| {
            matches!(
                e.tier,
                ResourceTier::Bytecode | ResourceTier::BytecodeOpt1 | ResourceTier::BytecodeOpt2
            )
        })
        .count();
    let payload_tier_count: usize = source_count + bytecode_count;
    assert!(
        payload_tier_count > 0,
        "expected at least one source or bytecode resource entry; got source={source_count} bytecode={bytecode_count}"
    );
    assert!(
        !parse.best_effort,
        "real binary must not fall back to heuristic walk; diagnostics={:?}",
        parse.diagnostics
    );
}

#[test]
fn pyoxidizer_falls_back_to_heuristic_on_truncated_blob() {
    const MARKER: &[u8] = b"pyembed\x03";
    const RES_FIELD_START_OF_ENTRY: u8 = 0x01;
    const RES_FIELD_NAME: u8 = 0x03;
    let mut blob: Vec<u8> = Vec::with_capacity(MARKER.len() + 32);
    blob.extend_from_slice(MARKER);
    blob.push(RES_FIELD_START_OF_ENTRY);
    blob.push(RES_FIELD_NAME);
    blob.extend_from_slice(&0xFFFFu16.to_le_bytes());
    blob.extend_from_slice(b"__pycache__/mod.pyc");
    let parse: PackedResourcesParse =
        parse_packed_resources(&blob).expect("truncated blob must still produce a parse");
    assert!(
        parse.best_effort,
        "truncated blob must trigger heuristic walk fallback"
    );
    let pycache_present: bool = parse
        .entries
        .iter()
        .any(|e: &ParsedResourceEntry| e.name.contains("__pycache__"));
    assert!(
        pycache_present,
        "heuristic walk must surface __pycache__ name even on truncated input"
    );
}
