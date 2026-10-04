#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CaptureOutcome, CommandSpec, Completion, Execution};
use disrobe_pass_sourcedefender::{
    ContainerVariant, LayeredRecovery, SourceRecoverOpts, SourceRecoverOutput,
    decrypt_pye_to_source, recover_from_marshal_bytes, recover_layered,
    recover_layered_with_modern_key,
};
use disrobe_py_marshal::PyVersion;
use disrobe_testkit::authorized_authored_source;
use regex::Regex;

const REAL_HELLO_PYE: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
const REAL_HELLO_PLAINTEXT: &str = include_str!("../../../corpus/python/sourcedefender/hello.py");
const CRAFTED_MODERN_KNOWN_KEY: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.pye");
const REAL_LEGACY_BYTECODE_PYE: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/legacy_bytecode.pye");
const PYTHON_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const CAPTURE_LIMIT: usize = 1 << 20;

#[derive(Debug, Clone)]
struct CpythonInvocation {
    program: PathBuf,
}

struct PythonRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").is_file() {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn ground_truth_source(rel: &str) -> PathBuf {
    let root: PathBuf = workspace_root();
    let relative: String = format!("corpus/python/sourcedefender/{rel}");
    authorized_authored_source(&root, &relative)
        .expect("the SourceDefender reference is an authorized authored source")
}

fn make_tmp(name: &str) -> (ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-sd-cpyexec-{name}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    (scratch, dir)
}

fn probe_cpython_314(invocation: &CpythonInvocation) -> bool {
    let Ok(execution): Result<Execution, _> = CommandSpec::new(&invocation.program, PROBE_TIMEOUT)
        .args([
            "-c",
            "import platform,sys;print(platform.python_implementation(),f'{sys.version_info.major}.{sys.version_info.minor}',sys.version_info.releaselevel,sep='|')",
        ])
        .capture_limits(CAPTURE_LIMIT, CAPTURE_LIMIT)
        .run()
    else {
        return false;
    };
    let Completion::Exited(status) = execution.completion else {
        return false;
    };
    let (CaptureOutcome::Complete(stdout), CaptureOutcome::Complete(stderr)) =
        (execution.stdout, execution.stderr)
    else {
        return false;
    };
    status.success()
        && !stdout.truncated
        && !stderr.truncated
        && String::from_utf8_lossy(&stdout.bytes).trim() == "CPython|3.14|final"
}

fn uv_python_314() -> Option<PathBuf> {
    let execution: Execution = CommandSpec::new("uv", PROBE_TIMEOUT)
        .args(["python", "find", "3.14"])
        .capture_limits(CAPTURE_LIMIT, CAPTURE_LIMIT)
        .run()
        .ok()?;
    let Completion::Exited(status) = execution.completion else {
        return None;
    };
    let (CaptureOutcome::Complete(stdout), CaptureOutcome::Complete(stderr)) =
        (execution.stdout, execution.stderr)
    else {
        return None;
    };
    if !status.success() || stdout.truncated || stderr.truncated {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&stdout.bytes).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

#[cfg(windows)]
fn windows_python_314() -> Option<PathBuf> {
    let execution: Execution = CommandSpec::new("py", PROBE_TIMEOUT)
        .args(["-3.14", "-c", "import sys;print(sys.executable)"])
        .capture_limits(CAPTURE_LIMIT, CAPTURE_LIMIT)
        .run()
        .ok()?;
    let Completion::Exited(status) = execution.completion else {
        return None;
    };
    let (CaptureOutcome::Complete(stdout), CaptureOutcome::Complete(stderr)) =
        (execution.stdout, execution.stderr)
    else {
        return None;
    };
    if !status.success() || stdout.truncated || stderr.truncated {
        return None;
    }
    let path: PathBuf = PathBuf::from(String::from_utf8_lossy(&stdout.bytes).trim().to_owned());
    path.is_file().then_some(path)
}

fn find_cpython_314() -> Option<CpythonInvocation> {
    let mut candidates: Vec<CpythonInvocation> = Vec::new();
    if let Some(program) = std::env::var_os("DISROBE_PYTHON") {
        candidates.push(CpythonInvocation {
            program: PathBuf::from(program),
        });
    }
    if let Some(program) = uv_python_314() {
        candidates.push(CpythonInvocation { program });
    }
    #[cfg(windows)]
    if let Some(program) = windows_python_314() {
        candidates.push(CpythonInvocation { program });
    }
    for program in ["python3.14", "python"] {
        candidates.push(CpythonInvocation {
            program: PathBuf::from(program),
        });
    }
    candidates
        .into_iter()
        .find(|candidate: &CpythonInvocation| probe_cpython_314(candidate))
}

fn require_cpython_314() -> CpythonInvocation {
    find_cpython_314().unwrap_or_else(|| {
        panic!(
            "final CPython 3.14 is mandatory for the SourceDefender execution oracle; install it through uv or point DISROBE_PYTHON at the interpreter"
        )
    })
}

fn complete_capture(outcome: CaptureOutcome, stream: &str) -> Result<Vec<u8>, String> {
    match outcome {
        CaptureOutcome::Complete(captured) if !captured.truncated => Ok(captured.bytes),
        CaptureOutcome::Complete(_) => {
            Err(format!("Python {stream} exceeded {CAPTURE_LIMIT} bytes"))
        }
        CaptureOutcome::Failed { source, .. } => {
            Err(format!("Python {stream} capture failed: {source}"))
        }
        CaptureOutcome::NotStarted => Err(format!("Python {stream} capture did not start")),
        CaptureOutcome::WorkerPanicked => Err(format!("Python {stream} capture worker panicked")),
        CaptureOutcome::WorkerUnresponsive => {
            Err(format!("Python {stream} capture worker did not finish"))
        }
    }
}

fn run_python_capture(python: &CpythonInvocation, script: &Path) -> Result<PythonRun, String> {
    let execution: Execution = CommandSpec::new(python.program.clone(), PYTHON_TIMEOUT)
        .arg(script.as_os_str().to_owned())
        .env("PYTHONHASHSEED", "0")
        .current_dir(workspace_root())
        .run()
        .map_err(|error| format!("interpreter did not run: {error}"))?;
    let Completion::Exited(status) = execution.completion else {
        return Err(format!("interpreter exceeded {PYTHON_TIMEOUT:?}"));
    };
    Ok(PythonRun {
        status,
        stdout: complete_capture(execution.stdout, "stdout")?,
        stderr: complete_capture(execution.stderr, "stderr")?,
    })
}

fn compare_recovered_behavior(
    label: &str,
    python: &CpythonInvocation,
    recovered_source: &str,
    ground_truth_rel: &str,
) -> Result<(), String> {
    let loader: Regex = Regex::new(r"(?m)\b(?:sourcedefender|marshal)\b|\bexec\s*\(")
        .expect("loader residue pattern");
    if loader.is_match(recovered_source) {
        return Err(format!(
            "{label}: loader residue remains in recovered source; refuse it before starting Python"
        ));
    }
    let ground_truth_path: PathBuf = ground_truth_source(ground_truth_rel);
    if !ground_truth_path.is_file() {
        return Err(format!(
            "{label}: ground-truth {ground_truth_rel} must exist in the corpus"
        ));
    }

    let (_scratch, tmp): (ScratchDir, PathBuf) = make_tmp(label);
    let recovered_path: PathBuf = tmp.join("recovered.py");
    std::fs::write(&recovered_path, recovered_source)
        .map_err(|error: std::io::Error| format!("{label}: write recovered source: {error}"))?;

    let recovered_run: PythonRun = run_python_capture(python, &recovered_path)
        .map_err(|error| format!("{label}: execute recovered source: {error}"))?;
    let truth_run: PythonRun = run_python_capture(python, &ground_truth_path)
        .map_err(|error| format!("{label}: execute ground truth: {error}"))?;

    if !recovered_run.status.success() {
        let recovered_stderr: String = String::from_utf8_lossy(&recovered_run.stderr).into_owned();
        return Err(format!(
            "{label}: final CPython 3.14 failed to execute the recovered source with exit {:?}: {recovered_stderr}\nsource:\n{recovered_source}",
            recovered_run.status.code()
        ));
    }
    if !truth_run.status.success() {
        let truth_stderr: String = String::from_utf8_lossy(&truth_run.stderr).into_owned();
        return Err(format!(
            "{label}: final CPython 3.14 failed to execute ground truth with exit {:?}: {truth_stderr}",
            truth_run.status.code()
        ));
    }
    if truth_run
        .stdout
        .iter()
        .all(|byte: &u8| byte.is_ascii_whitespace())
    {
        return Err(format!(
            "{label}: the ground-truth program produced no observable stdout"
        ));
    }
    if recovered_run.stdout != truth_run.stdout {
        let recovered_stdout: String = String::from_utf8_lossy(&recovered_run.stdout).into_owned();
        let truth_stdout: String = String::from_utf8_lossy(&truth_run.stdout).into_owned();
        return Err(format!(
            "{label}: exact stdout mismatch under final CPython 3.14\nexpected:\n{truth_stdout}\nrecovered:\n{recovered_stdout}"
        ));
    }
    Ok(())
}

fn assert_recovered_behaves_like_ground_truth(
    label: &str,
    python: &CpythonInvocation,
    recovered_source: &str,
    ground_truth_rel: &str,
) {
    let outcome: Result<(), String> =
        compare_recovered_behavior(label, python, recovered_source, ground_truth_rel);
    outcome.unwrap_or_else(|message: String| panic!("{message}"));
}

fn recover_legacy_bytecode_source() -> String {
    let Ok(rec): Result<LayeredRecovery, _> =
        recover_layered(REAL_LEGACY_BYTECODE_PYE, "legacy_bytecode.pye")
    else {
        unreachable!("real v15 --no-bytecode .pye must peel the legacy aes-256-ctr container")
    };
    assert_eq!(rec.variant, ContainerVariant::LegacyArmored);
    assert!(
        rec.wall.is_none(),
        "the basename-key legacy body is fully recoverable, not walled"
    );
    let Some(marshal): Option<Vec<u8>> = rec.recovered_marshal else {
        unreachable!("--no-bytecode payload is a marshalled code object, not inline source")
    };
    assert_eq!(
        marshal.first(),
        Some(&0x63u8),
        "the payload is a real CPython marshalled code object (TYPE_CODE)"
    );

    let opts: SourceRecoverOpts = SourceRecoverOpts {
        marshal_version: PyVersion::PY314,
        recurse_nested: true,
    };
    let Ok(out): Result<SourceRecoverOutput, _> =
        recover_from_marshal_bytes(&marshal, Some("legacy_bytecode.py".to_owned()), None, opts)
    else {
        unreachable!("the recovered marshal must load and route through py-decompile")
    };
    let Some(recovered): Option<String> = out.recovered_source else {
        unreachable!("py-decompile must emit Python source from the recovered marshal payload")
    };
    assert!(
        !out.code_object_summary.is_empty(),
        "the marshalled module must expose at least the top-level code object"
    );
    recovered
}

#[test]
fn legacy_free_hello_decrypts_to_the_published_plaintext() {
    let Ok(out): Result<SourceRecoverOutput, _> =
        decrypt_pye_to_source(REAL_HELLO_PYE, "hello.pye", SourceRecoverOpts::default())
    else {
        unreachable!("real hello.pye must decrypt to source through decrypt_pye_to_source")
    };
    let Some(recovered): Option<String> = out.recovered_source else {
        unreachable!("free-version hello.pye must recover an inline source string")
    };
    assert_eq!(
        recovered, REAL_HELLO_PLAINTEXT,
        "hello.pye must decrypt to the plaintext published beside it, byte for byte"
    );
}

#[test]
fn legacy_bytecode_marshal_decompiles_to_source_that_executes_like_original() {
    let python: CpythonInvocation = require_cpython_314();
    let recovered: String = recover_legacy_bytecode_source();
    assert_recovered_behaves_like_ground_truth(
        "legacy_bytecode",
        &python,
        &recovered,
        "legacy_bytecode.py",
    );
}

#[test]
fn loader_residue_is_refused_before_starting_python() {
    let python: CpythonInvocation = CpythonInvocation {
        program: PathBuf::from("disrobe-deliberately-unavailable-python"),
    };
    for source in ["import sourcedefender", "import marshal", "exec('pass')"] {
        let fault: String =
            compare_recovered_behavior("residue", &python, source, "legacy_bytecode.py")
                .expect_err("loader residue must be rejected before interpreter discovery");
        assert!(
            fault.contains("loader residue"),
            "unexpected refusal: {fault}"
        );
    }
}

#[test]
fn legacy_bytecode_stdout_oracle_rejects_observable_mutation() {
    let python: CpythonInvocation = require_cpython_314();
    let recovered: String = recover_legacy_bytecode_source();
    let baseline: Result<(), String> = compare_recovered_behavior(
        "legacy_bytecode_mutation_baseline",
        &python,
        &recovered,
        "legacy_bytecode.py",
    );
    baseline.unwrap_or_else(|message: String| panic!("{message}"));

    let mutated: String = format!("{recovered}\nprint(\"mutation-kill\")\n");
    let outcome: Result<(), String> = compare_recovered_behavior(
        "legacy_bytecode_mutation",
        &python,
        &mutated,
        "legacy_bytecode.py",
    );
    let fault: String = outcome.expect_err("the observable source mutation must fail the oracle");
    assert!(
        fault.contains("exact stdout mismatch"),
        "the mutation must be killed specifically by the exact-byte comparator, got: {fault}"
    );
}

#[test]
fn modern_gcm_recovered_source_matches_authored_bytes() {
    let mut key: [u8; 32] = [0u8; 32];
    for (i, b) in key.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap_or(0);
    }
    let Ok(rec): Result<LayeredRecovery, _> =
        recover_layered_with_modern_key(CRAFTED_MODERN_KNOWN_KEY, "crafted.pye", &key)
    else {
        unreachable!("keyed modern recovery must peel and decrypt the crafted AES-GCM body")
    };
    assert_eq!(rec.variant, ContainerVariant::ModernHex);
    let Some(recovered): Option<String> = rec.recovered_source else {
        unreachable!("modern free/source body must recover its original source string")
    };

    assert_eq!(
        recovered,
        include_str!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.py"),
        "known-key AES-GCM fixture must recover the authored source byte for byte",
    );
}
