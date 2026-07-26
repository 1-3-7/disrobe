#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr
)]
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_core::scratch::{ScratchDir, scratch_root};
use disrobe_pass_pyarmor::{UnpackOptions, UnpackOutput, unpack_wrapper_text_with_options};

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").is_file() {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn sample_dir(rel: &str) -> Option<PathBuf> {
    let dir: PathBuf = workspace_root().join("corpus/python/pyarmor").join(rel);
    dir.join("known_plaintext.py").is_file().then_some(dir)
}

fn make_scratch(name: &str) -> ScratchDir {
    ScratchDir::create(&format!("pyarmor-cpyexec-{name}")).expect("scratch dir")
}

fn python_for_minor(minor: u8) -> Option<String> {
    let candidates: [Vec<String>; 3] = [
        vec!["py".to_owned(), format!("-3.{minor}")],
        vec![format!("python3.{minor}")],
        vec![format!("python3.{minor}.exe")],
    ];
    for argv in candidates {
        let (prog, args): (&String, &[String]) = (&argv[0], &argv[1..]);
        let out: std::io::Result<std::process::Output> = Command::new(prog)
            .args(args)
            .arg("-c")
            .arg("import sys;print(sys.version_info[:2])")
            .output();
        if let Ok(o) = out
            && o.status.success()
        {
            let stdout: String = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            if stdout.contains(&format!("3, {minor}")) {
                return Some(argv.join(" "));
            }
        }
    }
    None
}

const PROBE_SRC: &str = r#"
import marshal, sys, io

with open(sys.argv[1], "rb") as f:
    data = f.read()
if data[:4] != sys.argv[2].encode("latin1"):
    print("MAGIC_MISMATCH", data[:4].hex(), sys.argv[2].encode('latin1').hex())
    sys.exit(10)
code = marshal.loads(data[16:])

ns = {"__name__": "recovered_pyarmor_module"}
buf = io.StringIO(); old = sys.stdout; sys.stdout = buf
try:
    exec(code, ns)
except BaseException as e:
    sys.stdout = old
    print("EXEC_FAIL", type(e).__name__, e)
    sys.exit(11)
finally:
    sys.stdout = old

checks = []
try:
    checks.append(ns["add"](2, 3) == 5)
    checks.append(ns["classify"](-1) == "negative")
    checks.append(ns["classify"](0) == "zero")
    checks.append(ns["classify"](7) == "positive")
    c = ns["Counter"](10)
    checks.append(c.increment(5) == 15)
    checks.append(ns["SECRET_TOKEN"] == "disrobe-vmc-oracle-12345")
    b2 = io.StringIO(); old = sys.stdout; sys.stdout = b2
    try:
        total = ns["main"]()
    finally:
        sys.stdout = old
    checks.append(total == 16)
    checks.append("disrobe-vmc-oracle-12345 16" in b2.getvalue())
except BaseException as e:
    print("CHECK_ERROR", type(e).__name__, e)
    sys.exit(12)

if all(checks):
    print("OK")
    sys.exit(0)
print("CHECK_FAIL", checks)
sys.exit(13)
"#;

fn recover_pyc(rel: &str) -> Option<(Vec<u8>, u8)> {
    let dir: PathBuf = sample_dir(rel)?;
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let text: String = std::fs::read_to_string(&wrapper_path).expect("wrapper readable");
    let out: UnpackOutput =
        unpack_wrapper_text_with_options(&text, &wrapper_path, &UnpackOptions::default())
            .expect("v9 sibling-runtime recovery succeeds");
    let pyc: Vec<u8> = out.pyc.expect("recovery emits a real pyc");
    let minor: u8 = out
        .py_version
        .map(|v| v.minor)
        .or(out.detection.python_minor)
        .expect("recovered pyc carries a python version");
    Some((pyc, minor))
}

fn magic_ascii(pyc: &[u8]) -> String {
    pyc[..4].iter().map(|&b| b as char).collect()
}

fn run_cpython_oracle(rel: &str) {
    let Some((pyc, minor)): Option<(Vec<u8>, u8)> = recover_pyc(rel) else {
        eprintln!("{rel}: sample absent; skipping");
        return;
    };
    let Some(python): Option<String> = python_for_minor(minor) else {
        eprintln!(
            "{rel}: no CPython 3.{minor} on PATH; skipping the execution oracle (env-robust skip)"
        );
        return;
    };

    let scratch: ScratchDir = make_scratch(rel.replace(['/', '\\'], "_").as_str());
    let tmp: &Path = scratch.path();
    let pyc_path: PathBuf = tmp.join("recovered.pyc");
    let probe_path: PathBuf = tmp.join("probe.py");
    std::fs::write(&pyc_path, &pyc).expect("write pyc");
    std::fs::write(&probe_path, PROBE_SRC).expect("write probe");

    let mut parts: std::str::SplitWhitespace<'_> = python.split_whitespace();
    let prog: &str = parts.next().expect("python program");
    let mut cmd: Command = Command::new(prog);
    for a in parts {
        cmd.arg(a);
    }
    let output: std::process::Output = cmd
        .arg(&probe_path)
        .arg(&pyc_path)
        .arg(magic_ascii(&pyc))
        .output()
        .expect("spawn cpython");

    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    let stderr: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "{rel}: real CPython 3.{minor} must load AND execute the recovered pyc with behavior equal to the pre-obfuscation source (exit {:?}).\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(
        stdout.contains("OK"),
        "{rel}: CPython behavioral equivalence oracle must report OK; got stdout: {stdout} stderr: {stderr}"
    );
}

#[test]
fn recovered_925_default_executes_in_real_cpython() {
    run_cpython_oracle("v9_latest_925/default");
}

#[test]
fn recovered_925_nowrap_executes_in_real_cpython() {
    run_cpython_oracle("v9_latest_925/nowrap");
}

#[test]
fn recovered_925_restrict_executes_in_real_cpython() {
    run_cpython_oracle("v9_latest_925/restrict");
}

#[test]
fn recovered_license_id_default_executes_in_real_cpython() {
    run_cpython_oracle("v9_license_id_015009/default");
}

#[test]
fn recovered_license_id_mixstr_executes_in_real_cpython() {
    run_cpython_oracle("v9_license_id_015009/mixstr");
}

#[test]
fn recovered_license_id_restrict_executes_in_real_cpython() {
    run_cpython_oracle("v9_license_id_015009/restrict");
}

fn wrapper_path_for(rel: &str) -> Option<PathBuf> {
    sample_dir(rel).map(|d: PathBuf| d.join("known_plaintext.py"))
}

#[test]
fn magic_is_real_cpython_pyc_header() {
    let Some(_wp): Option<PathBuf> = wrapper_path_for("v9_latest_925/default") else {
        eprintln!("sample absent; skipping");
        return;
    };
    let (pyc, _minor): (Vec<u8>, u8) =
        recover_pyc("v9_latest_925/default").expect("sample present");
    assert!(
        pyc.len() > 16 && pyc[2] == 0x0d && pyc[3] == 0x0a,
        "recovered pyc must carry a real CPython pyc header (0x0D 0x0A at [2..4]); head {:?}",
        &pyc[..pyc.len().min(4)]
    );
}

#[test]
fn probe_directories_live_under_the_namespaced_scratch_root() {
    let scratch: ScratchDir = make_scratch("selfcheck");
    assert!(
        scratch.path().starts_with(scratch_root()),
        "a probe directory must sit under the namespaced scratch root, not loose in the temp root: {}",
        scratch.path().display()
    );
}
