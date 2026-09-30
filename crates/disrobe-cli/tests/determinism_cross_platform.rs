#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
}

fn corpus_path(rel: &str) -> PathBuf {
    workspace_root().join("corpus").join(rel)
}

fn disrobe_bin() -> PathBuf {
    let bin: PathBuf = PathBuf::from(
        std::env::var_os("DISROBE_BIN")
            .expect("DISROBE_BIN must name the current disrobe binary built for this caller test"),
    );
    assert!(
        bin.is_file(),
        "DISROBE_BIN does not name a file: {}",
        bin.display()
    );
    bin
}

fn temp_dir(stem: &str) -> disrobe_core::scratch::ScratchDir {
    let purpose: String = format!("disrobe-determinism-{stem}");
    disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch directory")
}

fn run_disrobe(args: &[String]) -> Output {
    let bin: PathBuf = disrobe_bin();
    Command::new(&bin)
        .args(args)
        .env_remove("RUST_LOG")
        .env_remove("DISROBE_LOG")
        .env_remove("SOURCE_DATE_EPOCH")
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
    let input: PathBuf =
        corpus_path("python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc");
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
    let recovered: PathBuf = out_dir.join("edge_cases_3_12.cpython-312.py");
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
    ("py-decompile-edge-cases-3.12", recover_py_decompile),
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

type Snapshot = BTreeMap<String, Vec<u8>>;

fn snapshot(root: &Path) -> Snapshot {
    let mut files: Snapshot = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let relative: String = entry
            .path()
            .strip_prefix(root)
            .expect("walked entry is under root")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes: Vec<u8> = std::fs::read(entry.path()).unwrap_or_else(|e: std::io::Error| {
            panic!("reading run output {}: {e}", entry.path().display())
        });
        files.insert(relative, bytes);
    }
    assert!(
        !files.is_empty(),
        "the run at {} produced no output files",
        root.display()
    );
    files
}

fn differing_files(left: &Snapshot, right: &Snapshot) -> Vec<String> {
    left.keys()
        .chain(right.keys())
        .filter(|name: &&String| left.get(*name) != right.get(*name))
        .cloned()
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

fn run_into(out: &Path, args: &[String]) -> (Output, Snapshot) {
    if out.exists() {
        std::fs::remove_dir_all(out).expect("clear the previous run");
    }
    let output: Output = run_disrobe(args);
    assert!(
        output.status.success(),
        "disrobe {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let files: Snapshot = snapshot(out);
    (output, files)
}

#[test]
fn two_auto_runs_over_one_input_write_identical_bytes() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-twice");
    let input: PathBuf = scratch.path().join("edge_cases_3_12.pyc");
    std::fs::copy(
        corpus_path("python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc"),
        &input,
    )
    .expect("stage the fixture");
    let out: PathBuf = scratch.path().join("out");
    let args: Vec<String> = vec![
        "--json".to_string(),
        "auto".to_string(),
        input.to_string_lossy().into_owned(),
        "--out".to_string(),
        out.to_string_lossy().into_owned(),
    ];
    let (first_run, first): (Output, Snapshot) = run_into(&out, &args);
    std::thread::sleep(Duration::from_millis(1_100));
    let (second_run, second): (Output, Snapshot) = run_into(&out, &args);
    assert_eq!(
        first_run.stdout, second_run.stdout,
        "auto --json stdout differs between two runs over one input"
    );
    assert_eq!(
        differing_files(&first, &second),
        Vec::<String>::new(),
        "output files differ between two runs over one input"
    );
}

fn add_recorded_duration(report_path: &Path, duration: u32) {
    let report: Vec<u8> = std::fs::read(report_path)
        .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", report_path.display()));
    let mut document: serde_json::Value =
        serde_json::from_slice(&report).unwrap_or_else(|error: serde_json::Error| {
            panic!("parse {}: {error}", report_path.display())
        });
    document
        .as_object_mut()
        .unwrap_or_else(|| panic!("{} is not an object", report_path.display()))
        .insert("duration_ms".to_string(), serde_json::Value::from(duration));
    let mutated: Vec<u8> =
        serde_json::to_vec_pretty(&document).expect("serialize the duration mutant");
    std::fs::write(report_path, mutated)
        .unwrap_or_else(|error: std::io::Error| panic!("write {}: {error}", report_path.display()));
}

#[test]
fn a_duration_mutant_in_actual_auto_output_turns_the_comparison_red() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("auto-duration-mutant");
    let input: PathBuf = scratch.path().join("edge_cases_3_12.pyc");
    std::fs::copy(
        corpus_path("python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc"),
        &input,
    )
    .expect("stage the fixture");
    let out: PathBuf = scratch.path().join("out");
    let args: Vec<String> = vec![
        "--json".to_string(),
        "auto".to_string(),
        input.to_string_lossy().into_owned(),
        "--out".to_string(),
        out.to_string_lossy().into_owned(),
    ];
    let (_, baseline): (Output, Snapshot) = run_into(&out, &args);
    add_recorded_duration(&out.join("report.json"), 7);
    let mutated: Snapshot = snapshot(&out);
    assert_eq!(
        differing_files(&baseline, &mutated),
        vec!["report.json".to_string()],
        "the direct-byte comparison must reject a duration field in auto output"
    );
}

fn stage_batch_input() -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-input");
    let dir: PathBuf = scratch.path().to_path_buf();
    for rel in [
        "python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc",
        "native/packers/kkrunchy/hello.packed.kkrunchy_classic.exe",
        "pickle/malicious/p3/reduce_os_system.pkl",
    ] {
        let src: PathBuf = corpus_path(rel);
        let file_name: &std::ffi::OsStr = src.file_name().expect("fixture has a file name");
        std::fs::copy(&src, dir.join(file_name)).expect("stage batch fixture");
    }
    (scratch, dir)
}

fn batch_args(input_dir: &Path, out: &Path, jobs: u32) -> Vec<String> {
    vec![
        "--json".to_string(),
        "auto".to_string(),
        input_dir.to_string_lossy().into_owned(),
        "--out".to_string(),
        out.to_string_lossy().into_owned(),
        "--jobs".to_string(),
        jobs.to_string(),
    ]
}

#[test]
#[ignore = "runs on a single CI leg via an explicit `--ignored` invocation, not the default workspace sweep"]
fn batch_jobs_does_not_change_recovered_output() {
    let (_input_scratch, input_dir): (disrobe_core::scratch::ScratchDir, PathBuf) =
        stage_batch_input();
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("batch-out");
    let out: PathBuf = out_scratch.path().join("out");
    let (single_run, single): (Output, Snapshot) = run_into(&out, &batch_args(&input_dir, &out, 1));
    let (multi_run, multi): (Output, Snapshot) = run_into(&out, &batch_args(&input_dir, &out, 4));
    assert_eq!(
        single_run.stdout, multi_run.stdout,
        "auto --json stdout differs between --jobs 1 and --jobs 4"
    );
    assert_eq!(
        differing_files(&single, &multi),
        Vec::<String>::new(),
        "batch output differs between --jobs 1 and --jobs 4 over the same input directory"
    );
}
