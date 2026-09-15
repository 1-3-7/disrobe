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

const BATCH_PROVENANCE_NAMES: &[&str] = &[
    "manifest.json",
    "chain.json",
    "recovery.json",
    "report.json",
    "report.sarif",
];

const RUN_DURATION_KEYS: &[&str] = &["duration_ms", "total_ms"];

const RUN_CONFIGURATION_KEYS: &[&str] = &["jobs"];

const RUN_CLOCK_KEYS: &[&str] = &[
    "generated_at",
    "analysis_started",
    "analysis_ended",
    "startTimeUtc",
    "endTimeUtc",
    "timestamp",
    "created",
    "modified",
];

const CANONICAL_OUT_ROOT: &str = "<batch-out>";

const CANONICAL_RUN_CLOCK: &str = "\"<run-clock>\"";

fn json_string_body(text: &str) -> String {
    let quoted: String = serde_json::to_string(text).expect("encode path as JSON string");
    quoted[1..quoted.len() - 1].to_owned()
}

fn out_root_spellings(root: &Path) -> Vec<String> {
    let mut roots: Vec<String> = vec![root.display().to_string()];
    if let Ok(resolved) = std::fs::canonicalize(root) {
        let resolved: String = resolved.display().to_string();
        if let Some(verbatim_free) = resolved.strip_prefix(r"\\?\") {
            roots.push(verbatim_free.to_owned());
        }
        roots.push(resolved);
    }
    let mut spellings: Vec<String> = Vec::new();
    for native in roots {
        let slashed: String = native.replace('\\', "/");
        for form in [
            json_string_body(&native),
            json_string_body(&slashed),
            native,
            slashed,
        ] {
            if !spellings.contains(&form) {
                spellings.push(form);
            }
        }
    }
    spellings.sort_by_key(|form: &String| std::cmp::Reverse(form.len()));
    spellings
}

fn json_scalar_end(text: &str, start: usize) -> Option<usize> {
    let bytes: &[u8] = text.as_bytes();
    match bytes.get(start)? {
        b'"' => {
            let mut index: usize = start + 1;
            while let Some(byte) = bytes.get(index) {
                match byte {
                    b'\\' => index += 2,
                    b'"' => return Some(index + 1),
                    _ => index += 1,
                }
            }
            None
        }
        b'0'..=b'9' => Some(
            bytes[start..]
                .iter()
                .position(|byte: &u8| !byte.is_ascii_digit())
                .map_or(bytes.len(), |offset: usize| start + offset),
        ),
        _ => None,
    }
}

fn replace_key_values(text: &str, key: &str, numeric: bool, placeholder: &str) -> String {
    let needle: String = format!("\"{key}\": ");
    let mut canonical: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    while let Some(offset) = text[cursor..].find(&needle) {
        let value_start: usize = cursor + offset + needle.len();
        canonical.push_str(&text[cursor..value_start]);
        let shape_matches: bool = text
            .as_bytes()
            .get(value_start)
            .is_some_and(|byte: &u8| byte.is_ascii_digit() == numeric);
        match json_scalar_end(text, value_start).filter(|_: &usize| shape_matches) {
            Some(value_end) => {
                canonical.push_str(placeholder);
                cursor = value_end;
            }
            None => cursor = value_start,
        }
    }
    canonical.push_str(&text[cursor..]);
    canonical
}

fn canonical_provenance(bytes: &[u8], spellings: &[String]) -> Vec<u8> {
    let mut text: String = String::from_utf8(bytes.to_vec()).expect("provenance file is UTF-8");
    for spelling in spellings {
        text = text.replace(spelling.as_str(), CANONICAL_OUT_ROOT);
    }
    for key in RUN_DURATION_KEYS.iter().chain(RUN_CONFIGURATION_KEYS) {
        text = replace_key_values(&text, key, true, "0");
    }
    for key in RUN_CLOCK_KEYS {
        text = replace_key_values(&text, key, false, CANONICAL_RUN_CLOCK);
    }
    text.into_bytes()
}

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
    let spellings: Vec<String> = out_root_spellings(root);
    let mut entries: Vec<(String, blake3::Hash)> = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let is_provenance: bool = entry
            .file_name()
            .to_str()
            .is_some_and(|n: &str| BATCH_PROVENANCE_NAMES.contains(&n));
        let relative: PathBuf = entry
            .path()
            .strip_prefix(root)
            .expect("walked entry is under root")
            .to_path_buf();
        let relative_display: String = relative.to_string_lossy().replace('\\', "/");
        let bytes: Vec<u8> = std::fs::read(entry.path()).unwrap_or_else(|e: std::io::Error| {
            panic!("reading batch output {}: {e}", entry.path().display())
        });
        let hashed: Vec<u8> = if is_provenance {
            canonical_provenance(&bytes, &spellings)
        } else {
            bytes
        };
        entries.push((relative_display, blake3::hash(&hashed)));
    }
    assert!(
        !entries.is_empty(),
        "batch run at {} produced no output files",
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
