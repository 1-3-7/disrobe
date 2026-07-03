#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_SWIFT_OBJC_DEBUG_HARNESS";

fn fat_fixture_path() -> PathBuf {
    let manifest_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root: &Path = manifest_dir
        .ancestors()
        .nth(2)
        .expect("workspace root above crate");
    workspace_root
        .join("corpus")
        .join("mac")
        .join("megafile")
        .join("EdgeCases.fat")
}

fn run_harness(debug: Option<&str>, json: bool) -> Output {
    let exe: PathBuf = std::env::current_exe().expect("test executable path");
    let mut cmd: Command = Command::new(exe);
    cmd.env(HARNESS_ENV, "1");
    cmd.env_remove("DISROBE_DEBUG");
    cmd.env_remove("DISROBE_DEBUG_FORMAT");
    cmd.env("NO_COLOR", "1");
    if let Some(spec) = debug {
        cmd.env("DISROBE_DEBUG", spec);
    }
    if json {
        cmd.env("DISROBE_DEBUG_FORMAT", "json");
    }
    cmd.arg("--ignored");
    cmd.arg("--exact");
    cmd.arg("--nocapture");
    cmd.arg("--test-threads=1");
    cmd.arg("harness_entrypoint");
    cmd.output().expect("spawn harness child")
}

#[test]
#[ignore = "spawned as a subprocess by the debug-framework contract tests"]
fn harness_entrypoint() {
    if std::env::var_os(HARNESS_ENV).is_none() {
        return;
    }
    let path: PathBuf = fat_fixture_path();
    let bytes: Vec<u8> =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()));
    let report: disrobe_pass_swift_objc::pass::SwiftObjcReport =
        disrobe_pass_swift_objc::pass::analyze(&bytes).expect("fat mach-o analyzes");
    assert_eq!(
        report.container,
        disrobe_pass_swift_objc::pass::ContainerKind::MachO
    );
    assert!(
        !report.fat_entries.is_empty(),
        "EdgeCases.fat must walk to fat slices"
    );
}

fn fixture_present() -> bool {
    fat_fixture_path().is_file()
}

#[test]
fn unset_is_zero_overhead() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:swift-objc]"),
        "DISROBE_DEBUG unset must emit no swift-objc debug output, got:\n{stderr}"
    );
}

#[test]
fn set_emits_decision_points() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("swift-objc"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:swift-objc] === swift-objc analyze ==="),
        "expected the analyze section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:swift-objc] classify = mach-o"),
        "expected the mach-o classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:swift-objc] fat-arch-count ="),
        "expected the fat-arch-count decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:swift-objc] slice-header ="),
        "expected the per-slice header facts, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:swift-objc] swift-demangle ="),
        "expected the swift demangle decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:swift-objc] objc-metadata ="),
        "expected the objc metadata decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_swift_objc() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:swift-objc]"),
        "a sibling scope must not enable swift-objc output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    if !fixture_present() {
        return;
    }
    let out: Output = run_harness(Some("swift-objc"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"swift-objc\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several swift-objc json events, got {}:\n{stderr}",
        events.len()
    );
    for line in &events {
        let value: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid json line {line:?}: {e}"));
        assert!(
            value.is_object(),
            "each debug line must be a json object: {line}"
        );
        assert_eq!(
            value.get("scope").and_then(serde_json::Value::as_str),
            Some("swift-objc"),
            "every swift-objc event carries scope=swift-objc: {line}"
        );
    }
}
