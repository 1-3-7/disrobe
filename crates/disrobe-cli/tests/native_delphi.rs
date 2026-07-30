#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{Run, run_disrobe, temp_dir, temp_path, write_bytes};

#[cfg(windows)]
const SYSTEM_DLLS: [&str; 4] = [
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\System32\ntdll.dll",
    r"C:\Windows\System32\user32.dll",
    r"C:\Windows\System32\shell32.dll",
];

fn delphi_marker_pe() -> Vec<u8> {
    let mut bytes: Vec<u8> = disrobe_pass_native::fixtures::minimal_pe32();
    bytes.extend_from_slice(b"SOFTWARE\\Borland\\Delphi\x00");
    bytes.extend_from_slice(b"System.SysUtils\x00");
    bytes
}

fn non_delphi_pe() -> Vec<u8> {
    disrobe_pass_native::fixtures::minimal_pe32()
}

#[test]
#[cfg(windows)]
fn real_system_dlls_are_reported_as_not_delphi() {
    let mut checked: usize = 0;
    for path in SYSTEM_DLLS {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        checked += 1;
        let r: Run = run_disrobe(&["native", "delphi", path]);
        assert_eq!(
            r.code, 0,
            "{path}: exit code. stdout={} stderr={}",
            r.stdout, r.stderr
        );
        assert!(
            r.stdout.contains("native delphi: not a Delphi binary"),
            "{path} must be reported as not a Delphi binary. stdout={}",
            r.stdout
        );
        assert!(
            !r.stdout.contains("built with Delphi or C++Builder"),
            "{path} must not carry a Delphi verdict. stdout={}",
            r.stdout
        );
        assert!(
            !r.stdout.contains("class(es) recovered") && !r.stdout.contains("recovered ("),
            "{path} must not claim recovered classes. stdout={}",
            r.stdout
        );
    }
    assert!(checked > 0, "no real system DLL was readable for the check");
}

#[test]
#[cfg(windows)]
fn real_system_dll_json_names_no_delphi_release() {
    let path: &str = SYSTEM_DLLS[0];
    if !std::path::Path::new(path).exists() {
        return;
    }
    let r: Run = run_disrobe(&["native", "delphi", path, "--json"]);
    assert_eq!(r.code, 0, "exit code. stderr={}", r.stderr);
    let report: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("--json must emit one parseable report");
    assert_eq!(report["is_delphi"], serde_json::Value::Bool(false));
    assert_eq!(report["rtti_present"], serde_json::Value::Bool(false));
    assert_eq!(
        report["classes"].as_array().map(Vec::len),
        Some(0),
        "no class may be recovered from {path}"
    );
    assert!(
        report["version"].get("product").is_none(),
        "{path} must not be named as a Delphi release: {}",
        report["version"]
    );
}

#[test]
fn a_delphi_marked_image_with_no_rtti_is_not_reported_as_non_delphi() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("delphi-marker", "exe");
    write_bytes(&input, &delphi_marker_pe());

    let r: Run = run_disrobe(&["native", "delphi", input.to_str().unwrap()]);
    assert_eq!(r.code, 0, "exit code. stderr={}", r.stderr);
    assert!(
        r.stdout.contains("native delphi: OK"),
        "a marked image is a Delphi binary. stdout={}",
        r.stdout
    );
    assert!(
        r.stdout.contains("built with Delphi or C++Builder"),
        "the verdict must name the toolchain. stdout={}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("0 recovered; this image is Delphi-built with no readable RTTI"),
        "zero classes must read as a recovery outcome, not as a non-Delphi verdict. stdout={}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("not a Delphi binary"),
        "a Delphi-marked image must never take the non-Delphi verdict. stdout={}",
        r.stdout
    );
}

#[test]
fn an_unmarked_image_is_reported_as_not_delphi() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("delphi-absent", "exe");
    write_bytes(&input, &non_delphi_pe());

    let r: Run = run_disrobe(&["native", "delphi", input.to_str().unwrap()]);
    assert_eq!(r.code, 0, "exit code. stderr={}", r.stderr);
    assert!(
        r.stdout.contains("native delphi: not a Delphi binary"),
        "stdout={}",
        r.stdout
    );
    assert!(
        !r.stdout.contains("classes:"),
        "a non-Delphi verdict must not print a class table. stdout={}",
        r.stdout
    );
}

#[test]
fn json_carries_the_delphi_verdict_and_the_out_path_writes_the_same_report() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("delphi-json", "exe");
    write_bytes(&input, &delphi_marker_pe());
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("delphi-json-out");
    let out: PathBuf = out_scratch.path().join("delphi.json");

    let r: Run = run_disrobe(&[
        "native",
        "delphi",
        input.to_str().unwrap(),
        "--json",
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "exit code. stderr={}", r.stderr);
    let stdout_report: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("--json must emit one parseable report");
    assert_eq!(stdout_report["is_delphi"], serde_json::Value::Bool(true));
    assert_eq!(
        stdout_report["rtti_present"],
        serde_json::Value::Bool(false)
    );

    let written: String = std::fs::read_to_string(&out).expect("--out must write the report");
    let file_report: serde_json::Value =
        serde_json::from_str(&written).expect("the written report must parse");
    assert_eq!(
        file_report, stdout_report,
        "--out and --json must carry the same report"
    );
}

#[test]
fn dry_run_withholds_the_out_file() {
    let (_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("delphi-dryrun", "exe");
    write_bytes(&input, &delphi_marker_pe());
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("delphi-dryrun-out");
    let out: PathBuf = out_scratch.path().join("nested").join("delphi.json");

    let r: Run = run_disrobe(&[
        "--dry-run",
        "native",
        "delphi",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(r.code, 0, "exit code. stderr={}", r.stderr);
    assert!(
        r.stdout.contains("dry-run:      no file written"),
        "stdout={}",
        r.stdout
    );
    assert!(!out.exists(), "--dry-run must not write {}", out.display());
}

#[test]
#[cfg(feature = "chain")]
fn auto_attaches_the_delphi_report_only_when_detection_fires() {
    let (_marked_scratch, marked): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-delphi-marked", "exe");
    write_bytes(&marked, &delphi_marker_pe());
    let (_plain_scratch, plain): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("auto-delphi-plain", "exe");
    write_bytes(&plain, &non_delphi_pe());

    let marked_out: disrobe_core::scratch::ScratchDir = temp_dir("auto-delphi-marked-out");
    let marked_run: Run = run_disrobe(&[
        "auto",
        marked.to_str().unwrap(),
        "--out",
        marked_out.path().to_str().unwrap(),
    ]);
    assert_eq!(
        marked_run.code, 0,
        "exit code. stderr={}",
        marked_run.stderr
    );
    assert!(
        marked_run
            .stdout
            .contains("delphi: built with Delphi or C++Builder"),
        "the chain must surface the Delphi verdict. stdout={}",
        marked_run.stdout
    );
    assert!(
        marked_run.stdout.contains("delphi note: "),
        "the chain must surface the report notes. stdout={}",
        marked_run.stdout
    );
    let sidecar: PathBuf = marked_out.path().join("delphi.json");
    assert!(
        sidecar.exists(),
        "the chain must write {}",
        sidecar.display()
    );
    let written: String = std::fs::read_to_string(&sidecar).expect("read the chain sidecar");
    let report: serde_json::Value = serde_json::from_str(&written).expect("the sidecar must parse");
    assert_eq!(report["is_delphi"], serde_json::Value::Bool(true));

    let plain_out: disrobe_core::scratch::ScratchDir = temp_dir("auto-delphi-plain-out");
    let plain_run: Run = run_disrobe(&[
        "auto",
        plain.to_str().unwrap(),
        "--out",
        plain_out.path().to_str().unwrap(),
    ]);
    assert_eq!(plain_run.code, 0, "exit code. stderr={}", plain_run.stderr);
    assert!(
        !plain_run
            .stdout
            .lines()
            .any(|l: &str| l.trim_start().starts_with("delphi")),
        "a non-Delphi input must not reach the Delphi pass. stdout={}",
        plain_run.stdout
    );
    assert!(
        !plain_out.path().join("delphi.json").exists(),
        "a non-Delphi input must not produce a Delphi sidecar"
    );
}
