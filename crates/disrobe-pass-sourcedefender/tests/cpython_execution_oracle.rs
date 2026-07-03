#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

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

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

fn make_tmp(name: &str) -> PathBuf {
    let seq: u64 = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-sd-cpyexec-{name}-{}-{seq}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn any_cpython() -> Option<String> {
    let candidates: [Vec<String>; 3] = [
        vec!["python3".to_owned()],
        vec!["python".to_owned()],
        vec!["py".to_owned(), "-3".to_owned()],
    ];
    for argv in candidates {
        let (prog, args): (&String, &[String]) = (&argv[0], &argv[1..]);
        let out: std::io::Result<std::process::Output> = Command::new(prog)
            .args(args)
            .arg("-c")
            .arg("import sys;print(sys.version_info[0])")
            .output();
        if let Ok(o) = out
            && o.status.success()
            && String::from_utf8_lossy(&o.stdout).trim() == "3"
        {
            return Some(argv.join(" "));
        }
    }
    None
}

fn run_python_capture(python: &str, script: &std::path::Path) -> std::process::Output {
    let mut parts: std::str::SplitWhitespace<'_> = python.split_whitespace();
    let prog: &str = parts.next().expect("python program");
    let mut cmd: Command = Command::new(prog);
    for a in parts {
        cmd.arg(a);
    }
    cmd.arg(script).output().expect("spawn cpython")
}

fn assert_recovered_behaves_like_ground_truth(
    label: &str,
    python: &str,
    recovered_source: &str,
    ground_truth_rel: &str,
) {
    let ground_truth_path: PathBuf = ground_truth_source(ground_truth_rel);
    assert!(
        ground_truth_path.is_file(),
        "{label}: ground-truth {ground_truth_rel} must exist in the corpus"
    );

    let tmp: PathBuf = make_tmp(label);
    let recovered_path: std::path::PathBuf = tmp.join("recovered.py");
    std::fs::write(&recovered_path, recovered_source).expect("write recovered source");

    let recovered_run: std::process::Output = run_python_capture(python, &recovered_path);
    let truth_run: std::process::Output = run_python_capture(python, &ground_truth_path);

    let recovered_stdout: std::borrow::Cow<'_, str> =
        String::from_utf8_lossy(&recovered_run.stdout);
    let recovered_stderr: std::borrow::Cow<'_, str> =
        String::from_utf8_lossy(&recovered_run.stderr);
    let truth_stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&truth_run.stdout);
    let _ = std::fs::remove_dir_all(&tmp);

    assert!(
        recovered_run.status.success(),
        "{label}: real CPython must execute the disrobe-recovered source without error \
         (exit {:?}).\nstderr: {recovered_stderr}\nsource:\n{recovered_source}",
        recovered_run.status.code()
    );
    assert!(
        truth_run.status.success(),
        "{label}: the ground-truth .py must itself execute cleanly under CPython"
    );
    assert!(
        !truth_stdout.trim().is_empty(),
        "{label}: the ground-truth program must produce observable stdout, otherwise the \
         behavioral oracle asserts nothing"
    );
    assert_eq!(
        recovered_stdout, truth_stdout,
        "{label}: the recovered source must reproduce the exact runtime behavior of the \
         original .py (real-CPython stdout equivalence, not string identity)\n\
         recovered:\n{recovered_source}"
    );
}

#[test]
fn legacy_free_recovered_source_executes_like_original_in_real_cpython() {
    let Ok(out): Result<SourceRecoverOutput, _> =
        decrypt_pye_to_source(REAL_HELLO_PYE, "hello.pye", SourceRecoverOpts::default())
    else {
        unreachable!("real hello.pye must decrypt to source through decrypt_pye_to_source")
    };
    let Some(recovered): Option<String> = out.recovered_source else {
        unreachable!("free-version hello.pye must recover an inline source string")
    };

    let Some(python): Option<String> = any_cpython() else {
        eprintln!(
            "no CPython 3 on PATH; skipping the sourcedefender execution oracle (env-robust)"
        );
        return;
    };
    assert_recovered_behaves_like_ground_truth("legacy_hello", &python, &recovered, "hello.py");
}

#[test]
fn legacy_bytecode_marshal_decompiles_to_source_that_executes_like_original() {
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

    let Some(python): Option<String> = any_cpython() else {
        eprintln!(
            "no CPython 3 on PATH; skipping the sourcedefender execution oracle (env-robust)"
        );
        return;
    };
    assert_recovered_behaves_like_ground_truth(
        "legacy_bytecode",
        &python,
        &recovered,
        "legacy_bytecode.py",
    );
}

#[test]
fn modern_gcm_recovered_source_executes_like_original_in_real_cpython() {
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

    let Some(python): Option<String> = any_cpython() else {
        eprintln!(
            "no CPython 3 on PATH; skipping the sourcedefender execution oracle (env-robust)"
        );
        return;
    };
    assert_recovered_behaves_like_ground_truth(
        "modern_gcm",
        &python,
        &recovered,
        "crafted_modern_aesgcm_known_key.py",
    );
}
