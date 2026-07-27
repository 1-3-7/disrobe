#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn cargo_bin() -> PathBuf {
    let exe_name: &str = if cfg!(windows) {
        "disrobe.exe"
    } else {
        "disrobe"
    };
    let mut p: PathBuf = workspace_root();
    p.push("target");
    p.push(if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    });
    p.push(exe_name);
    p
}

fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-determinism-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_disrobe(args: &[String]) -> Output {
    let bin: PathBuf = cargo_bin();
    assert!(
        bin.exists(),
        "disrobe binary missing at {}; run `cargo build -p disrobe-cli` first",
        bin.display()
    );
    Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .output()
        .expect("spawn disrobe")
}

fn threaded_args(threads: Option<u32>, rest: &[&str]) -> Vec<String> {
    let mut args: Vec<String> = Vec::with_capacity(rest.len() + 2);
    if let Some(n) = threads {
        args.push("--threads".to_string());
        args.push(n.to_string());
    }
    args.extend(rest.iter().map(|s: &&str| (*s).to_string()));
    args
}

fn recover_py_decompile(threads: Option<u32>) -> Vec<u8> {
    let input: PathBuf = corpus_path("python/decompile/playground/edge_cases_2_7.pyc");
    let out_dir_scratch: disrobe_core::scratch::ScratchDir = temp_dir("py");
    let out_dir: PathBuf = out_dir_scratch.path().to_path_buf();
    let input_arg: String = input.to_string_lossy().into_owned();
    let out_arg: String = out_dir.to_string_lossy().into_owned();
    let args: Vec<String> =
        threaded_args(threads, &["py", "decompile", &input_arg, "--out", &out_arg]);
    let output: Output = run_disrobe(&args);
    assert!(
        output.status.success(),
        "py decompile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recovered: PathBuf = out_dir.join("edge_cases_2_7.py");
    std::fs::read(&recovered).unwrap_or_else(|e: std::io::Error| {
        panic!("reading recovered source {}: {e}", recovered.display())
    })
}

fn recover_native_unpack(threads: Option<u32>) -> Vec<u8> {
    let input: PathBuf = corpus_path("native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe");
    let out_file_scratch: disrobe_core::scratch::ScratchDir = temp_dir("native");
    let out_file: PathBuf = out_file_scratch.path().join("hello.unpacked.bin");
    let input_arg: String = input.to_string_lossy().into_owned();
    let out_arg: String = out_file.to_string_lossy().into_owned();
    let args: Vec<String> = threaded_args(
        threads,
        &["native", "unpack", &input_arg, "--out", &out_arg],
    );
    let output: Output = run_disrobe(&args);
    assert!(
        output.status.success(),
        "native unpack failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(&out_file).unwrap_or_else(|e: std::io::Error| {
        panic!("reading recovered image {}: {e}", out_file.display())
    })
}

fn recover_pickle_decompile(threads: Option<u32>) -> Vec<u8> {
    let input: PathBuf = corpus_path("pickle/malicious/p3/reduce_os_system.pkl");
    let out_file_scratch: disrobe_core::scratch::ScratchDir = temp_dir("pickle");
    let out_file: PathBuf = out_file_scratch.path().join("reduce_os_system.py");
    let input_arg: String = input.to_string_lossy().into_owned();
    let out_arg: String = out_file.to_string_lossy().into_owned();
    let args: Vec<String> = threaded_args(
        threads,
        &["pickle", "decompile", &input_arg, "--out", &out_arg],
    );
    let output: Output = run_disrobe(&args);
    assert!(
        output.status.success(),
        "pickle decompile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::read(&out_file).unwrap_or_else(|e: std::io::Error| {
        panic!("reading recovered source {}: {e}", out_file.display())
    })
}

type Recover = fn(Option<u32>) -> Vec<u8>;

const FIXTURES: &[(&str, Recover)] = &[
    ("py-decompile-edge-cases-2.7", recover_py_decompile),
    ("native-unpack-kkrunchy-classic", recover_native_unpack),
    (
        "pickle-decompile-reduce-os-system",
        recover_pickle_decompile,
    ),
];

fn hash_output_path() -> PathBuf {
    workspace_root()
        .join("target")
        .join("determinism-hashes.txt")
}

#[test]
fn cross_platform_fixture_hashes() {
    let mut lines: Vec<String> = Vec::with_capacity(FIXTURES.len());
    for (name, recover) in FIXTURES {
        let bytes: Vec<u8> = recover(None);
        assert!(!bytes.is_empty(), "{name}: recovered output is empty");
        let hash: blake3::Hash = blake3::hash(&bytes);
        lines.push(format!("{name} {hash}"));
    }
    lines.sort();
    let out_path: PathBuf = hash_output_path();
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).expect("create hash output dir");
    }
    std::fs::write(&out_path, lines.join("\n") + "\n").expect("write hash file");
    println!(
        "wrote {} fixture hash(es) to {}",
        lines.len(),
        out_path.display()
    );
}

const BATCH_SIDECAR_NAMES: &[&str] = &["manifest.json", "chain.json", "recovery.json"];

fn stage_batch_input() -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-input");
    let dir: PathBuf = scratch.path().to_path_buf();
    for rel in [
        "python/decompile/playground/edge_cases_2_7.pyc",
        "native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe",
        "pickle/malicious/p3/reduce_os_system.pkl",
    ] {
        let src: PathBuf = corpus_path(rel);
        let file_name: &std::ffi::OsStr = src.file_name().expect("fixture has a file name");
        std::fs::copy(&src, dir.join(file_name)).expect("stage batch fixture");
    }
    (scratch, dir)
}

fn run_batch(input_dir: &Path, jobs: u32) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-out");
    let out_dir: PathBuf = scratch.path().to_path_buf();
    let args: Vec<String> = vec![
        "auto".to_string(),
        input_dir.to_string_lossy().into_owned(),
        "--out".to_string(),
        out_dir.to_string_lossy().into_owned(),
        "--jobs".to_string(),
        jobs.to_string(),
    ];
    let output: Output = run_disrobe(&args);
    assert!(
        output.status.success(),
        "disrobe auto (batch, jobs={jobs}) failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (scratch, out_dir)
}

fn hash_batch_tree(root: &Path) -> blake3::Hash {
    let mut entries: Vec<(String, blake3::Hash)> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_name_is_sidecar: bool = entry
            .file_name()
            .to_str()
            .is_some_and(|n: &str| BATCH_SIDECAR_NAMES.contains(&n));
        if file_name_is_sidecar {
            continue;
        }
        let relative: PathBuf = entry
            .path()
            .strip_prefix(root)
            .expect("walked entry is under root")
            .to_path_buf();
        let relative_display: String = relative.to_string_lossy().replace('\\', "/");
        let bytes: Vec<u8> = std::fs::read(entry.path()).unwrap_or_else(|e: std::io::Error| {
            panic!("reading batch output {}: {e}", entry.path().display())
        });
        entries.push((relative_display, blake3::hash(&bytes)));
    }
    assert!(
        !entries.is_empty(),
        "batch run at {} produced no non-sidecar output files",
        root.display()
    );
    entries.sort_by(|a: &(String, blake3::Hash), b: &(String, blake3::Hash)| a.0.cmp(&b.0));
    let mut combined: Vec<u8> = Vec::new();
    for (relative, hash) in &entries {
        combined.extend_from_slice(relative.as_bytes());
        combined.push(0);
        combined.extend_from_slice(hash.as_bytes());
    }
    blake3::hash(&combined)
}

#[test]
#[ignore = "runs on a single CI leg via an explicit `--ignored` invocation, not the default workspace sweep"]
fn batch_jobs_does_not_change_recovered_output() {
    let (_input_scratch, input_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        stage_batch_input();
    let (_single_jobs_scratch, single_jobs_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        run_batch(&input_dir, 1);
    let (_multi_jobs_scratch, multi_jobs_out): (disrobe_core::scratch::ScratchDir, PathBuf) =
        run_batch(&input_dir, 4);
    let single_hash: blake3::Hash = hash_batch_tree(&single_jobs_out);
    let multi_hash: blake3::Hash = hash_batch_tree(&multi_jobs_out);
    assert_eq!(
        single_hash, multi_hash,
        "batch recovery output differs between --jobs 1 and --jobs 4 over the same input directory"
    );
}
