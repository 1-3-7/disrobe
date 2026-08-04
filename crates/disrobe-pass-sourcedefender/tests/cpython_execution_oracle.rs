#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_sourcedefender::{
    ContainerVariant, LayeredRecovery, SourceRecoverOpts, SourceRecoverOutput,
    decrypt_pye_to_source, recover_from_marshal_bytes, recover_layered,
    recover_layered_with_modern_key,
};
use disrobe_py_marshal::PyVersion;

const REAL_HELLO_PYE: &[u8] = include_bytes!("../../../corpus/python/sourcedefender/hello.pye");
const CRAFTED_MODERN_KNOWN_KEY: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/crafted_modern_aesgcm_known_key.pye");
const REAL_LEGACY_BYTECODE_PYE: &[u8] =
    include_bytes!("../../../corpus/python/sourcedefender/legacy_bytecode.pye");

#[derive(Debug, Clone)]
struct CpythonInvocation {
    program: PathBuf,
    prefix_args: Vec<OsString>,
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
    workspace_root()
        .join("corpus/python/sourcedefender")
        .join(rel)
}

fn make_tmp(name: &str) -> (ScratchDir, PathBuf) {
    let purpose: String = format!("disrobe-sd-cpyexec-{name}");
    let scratch: ScratchDir = ScratchDir::create(&purpose).expect("create scratch directory");
    let dir: PathBuf = scratch.path().to_path_buf();
    (scratch, dir)
}

fn probe_cpython_314(invocation: &CpythonInvocation) -> bool {
    let output: std::io::Result<Output> = Command::new(&invocation.program)
        .args(&invocation.prefix_args)
        .args([
            "-c",
            "import platform,sys;print(platform.python_implementation(),f'{sys.version_info.major}.{sys.version_info.minor}',sys.version_info.releaselevel,sep='|')",
        ])
        .stdin(Stdio::null())
        .output();
    output.is_ok_and(|found: Output| {
        found.status.success()
            && String::from_utf8_lossy(&found.stdout).trim() == "CPython|3.14|final"
    })
}

fn uv_python_314() -> Option<PathBuf> {
    let output: Output = Command::new("uv")
        .args(["python", "find", "3.14"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn find_cpython_314() -> Option<CpythonInvocation> {
    let mut candidates: Vec<CpythonInvocation> = Vec::new();
    if let Some(program) = std::env::var_os("DISROBE_PYTHON") {
        candidates.push(CpythonInvocation {
            program: PathBuf::from(program),
            prefix_args: Vec::new(),
        });
    }
    if let Some(program) = uv_python_314() {
        candidates.push(CpythonInvocation {
            program,
            prefix_args: Vec::new(),
        });
    }
    if cfg!(windows) {
        candidates.push(CpythonInvocation {
            program: PathBuf::from("py"),
            prefix_args: vec![OsString::from("-3.14")],
        });
    }
    for program in ["python3.14", "python"] {
        candidates.push(CpythonInvocation {
            program: PathBuf::from(program),
            prefix_args: Vec::new(),
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

fn run_python_capture(python: &CpythonInvocation, script: &Path) -> Result<Output, std::io::Error> {
    Command::new(&python.program)
        .args(&python.prefix_args)
        .arg(script)
        .env("PYTHONHASHSEED", "0")
        .stdin(Stdio::null())
        .output()
}

fn compare_recovered_behavior(
    label: &str,
    python: &CpythonInvocation,
    recovered_source: &str,
    ground_truth_rel: &str,
) -> Result<(), String> {
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

    let recovered_run: Output = run_python_capture(python, &recovered_path)
        .map_err(|error: std::io::Error| format!("{label}: spawn recovered source: {error}"))?;
    let truth_run: Output = run_python_capture(python, &ground_truth_path)
        .map_err(|error: std::io::Error| format!("{label}: spawn ground truth: {error}"))?;

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
fn legacy_free_recovered_source_executes_like_original_in_real_cpython() {
    let python: CpythonInvocation = require_cpython_314();
    let Ok(out): Result<SourceRecoverOutput, _> =
        decrypt_pye_to_source(REAL_HELLO_PYE, "hello.pye", SourceRecoverOpts::default())
    else {
        unreachable!("real hello.pye must decrypt to source through decrypt_pye_to_source")
    };
    let Some(recovered): Option<String> = out.recovered_source else {
        unreachable!("free-version hello.pye must recover an inline source string")
    };

    assert_recovered_behaves_like_ground_truth("legacy_hello", &python, &recovered, "hello.py");
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
fn modern_gcm_recovered_source_executes_like_original_in_real_cpython() {
    let python: CpythonInvocation = require_cpython_314();
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

    assert_recovered_behaves_like_ground_truth(
        "modern_gcm",
        &python,
        &recovered,
        "crafted_modern_aesgcm_known_key.py",
    );
}
