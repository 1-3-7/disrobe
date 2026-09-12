#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Write as _;
use std::process::{Command, Output};

const HARNESS_ENV: &str = "DISROBE_BINFMT_DEBUG_HARNESS";

fn incompressible(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state & 0xff) as u8
        })
        .collect()
}

fn synth_zip() -> Vec<u8> {
    let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> =
        zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let stored: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    writer.start_file("a.txt", stored).expect("stored entry");
    writer.write_all(b"alpha alpha alpha").expect("write a");
    let deflated: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    writer
        .start_file("pkg/b.txt", deflated)
        .expect("deflate entry");
    writer.write_all(&incompressible(4096)).expect("write b");
    writer.finish().expect("finish zip").into_inner()
}

fn run_harness(debug: Option<&str>, json: bool) -> Output {
    let exe: std::path::PathBuf = std::env::current_exe().expect("test executable path");
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
    let bytes: Vec<u8> = synth_zip();
    let kind: disrobe_binfmt::ContainerKind =
        disrobe_binfmt::detect_container(&bytes).expect("synth zip is detected");
    assert_eq!(kind, disrobe_binfmt::ContainerKind::Zip);
    let out_dir: tempfile::TempDir = tempfile::tempdir().expect("temp out dir");
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(kind, &bytes, out_dir.path()).expect("extract synth zip");
    assert_eq!(result.entries.len(), 2);
}

#[test]
fn unset_is_zero_overhead() {
    let out: Output = run_harness(None, false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let noise: String = stderr
        .lines()
        .filter(|line: &&str| !line.trim_start().starts_with("Compiling"))
        .filter(|line: &&str| !line.trim_start().starts_with("Finished"))
        .filter(|line: &&str| !line.trim_start().starts_with("Running"))
        .filter(|line: &&str| !line.trim().is_empty())
        .filter(|line: &&str| !line.contains("test result"))
        .filter(|line: &&str| !line.contains("running 1 test"))
        .filter(|line: &&str| !line.contains("harness_entrypoint"))
        .collect::<Vec<&str>>()
        .join("\n");
    assert!(
        !noise.contains("[debug:binfmt]"),
        "DISROBE_DEBUG unset must emit no binfmt debug output, got:\n{noise}"
    );
}

#[test]
fn set_emits_decision_points() {
    let out: Output = run_harness(Some("binfmt"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        stderr.contains("[debug:binfmt] === binfmt detect-container ==="),
        "expected the detect-container section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:binfmt] classify = zip"),
        "expected the classify decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:binfmt] === binfmt extract ==="),
        "expected the extract section header, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:binfmt] extraction-mode = Payload"),
        "expected the extraction-mode decision point, got:\n{stderr}"
    );
    assert!(
        stderr.contains("[debug:binfmt] entry a.txt ="),
        "expected the per-entry compression decision point, got:\n{stderr}"
    );
}

#[test]
fn other_scope_does_not_enable_binfmt() {
    let out: Output = run_harness(Some("jvm,native"), false);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        !stderr.contains("[debug:binfmt]"),
        "a sibling scope must not enable binfmt output, got:\n{stderr}"
    );
}

#[test]
fn json_mode_is_one_object_per_line() {
    let out: Output = run_harness(Some("binfmt"), true);
    assert!(out.status.success(), "child failed: {out:?}");
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    let events: Vec<&str> = stderr
        .lines()
        .filter(|line: &&str| line.trim_start().starts_with("{\"scope\":\"binfmt\""))
        .collect();
    assert!(
        events.len() >= 4,
        "expected several binfmt json events, got {}:\n{stderr}",
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
            Some("binfmt"),
            "every binfmt event carries scope=binfmt: {line}"
        );
    }
}
