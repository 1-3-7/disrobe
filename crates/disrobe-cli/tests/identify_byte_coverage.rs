#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unnecessary_debug_formatting
)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p
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

fn fixture(name: &str) -> PathBuf {
    let path: PathBuf = workspace_root()
        .join("corpus")
        .join("native")
        .join("formats")
        .join(name);
    assert!(
        path.is_file(),
        "this case grades byte accounting against a committed image, so its absence is a damaged \
         checkout: {}",
        path.display()
    );
    path
}

fn identify_json(name: &str, coverage: bool) -> serde_json::Value {
    let bin: PathBuf = cargo_bin();
    let mut command: Command = Command::new(&bin);
    command.arg("identify").arg(fixture(name)).arg("--json");
    if coverage {
        command.arg("--coverage");
    }
    let output: Output = command
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()));
    assert!(
        output.status.success(),
        "identify {name} exited {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "identify {name} must emit json: {error}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn byte_accounting_is_reached_only_when_the_flag_asks_for_it() {
    let without: serde_json::Value = identify_json("hello.pe64.exe", false);
    assert!(
        without.get("coverage").is_none(),
        "identify without --coverage must keep its existing document shape, got {without:#?}"
    );
    let with: serde_json::Value = identify_json("hello.pe64.exe", true);
    assert!(
        with.get("coverage").is_some(),
        "identify --coverage must carry the byte accounting, got {with:#?}"
    );
    assert_eq!(
        without.get("format"),
        with.get("format"),
        "asking for coverage must not change what the file is identified as"
    );
}

#[test]
fn the_reported_accounting_adds_up_to_the_real_file_length() {
    for name in ["hello.pe64.exe", "hello.elf64"] {
        let report: serde_json::Value = identify_json(name, true);
        let coverage: &serde_json::Value = report
            .get("coverage")
            .unwrap_or_else(|| panic!("{name} must carry coverage"));

        let on_disk: u64 = std::fs::metadata(fixture(name))
            .expect("stat the committed image")
            .len();
        let file_len: u64 = coverage
            .get("file_len")
            .and_then(serde_json::Value::as_u64)
            .expect("file_len");
        assert_eq!(
            file_len, on_disk,
            "{name} accounting must describe the whole committed file"
        );

        let claimed: u64 = coverage
            .get("claimed_bytes")
            .and_then(serde_json::Value::as_u64)
            .expect("claimed_bytes");
        let unclaimed: u64 = coverage
            .get("unclaimed_bytes")
            .and_then(serde_json::Value::as_u64)
            .expect("unclaimed_bytes");
        let slack: u64 = coverage
            .get("slack_bytes")
            .and_then(serde_json::Value::as_u64)
            .expect("slack_bytes");
        assert!(
            claimed > 0,
            "{name} is a real image, so its declared structures must claim bytes"
        );
        assert_eq!(
            claimed.saturating_add(unclaimed).saturating_add(slack),
            file_len,
            "{name} must place every byte in a claimed region, an unclaimed one, or alignment slack"
        );

        let regions: &Vec<serde_json::Value> = coverage
            .get("regions")
            .and_then(serde_json::Value::as_array)
            .expect("regions");
        let mapped: u64 = regions
            .iter()
            .map(|region: &serde_json::Value| {
                let start: u64 = region
                    .get("start")
                    .and_then(serde_json::Value::as_u64)
                    .expect("region start");
                let end: u64 = region
                    .get("end")
                    .and_then(serde_json::Value::as_u64)
                    .expect("region end");
                end.saturating_sub(start)
            })
            .sum();
        assert_eq!(
            mapped,
            file_len,
            "{name} regions must tile the whole file with no gap, got {} region(s)",
            regions.len()
        );

        let ratio: f64 = coverage
            .get("coverage_ratio")
            .and_then(serde_json::Value::as_f64)
            .expect("coverage_ratio");
        let expected: f64 = claimed as f64 / file_len as f64;
        assert!(
            (ratio - expected).abs() < 1e-9,
            "{name} published ratio {ratio} does not match {claimed} of {file_len}"
        );
    }
}

#[test]
fn an_appended_payload_is_reported_as_bytes_the_format_never_claims() {
    let base: PathBuf = fixture("hello.pe64.exe");
    let mut bytes: Vec<u8> = std::fs::read(&base).expect("read the committed image");
    let clean_len: u64 = u64::try_from(bytes.len()).expect("length fits an address");
    bytes.extend_from_slice(&[0xA5; 4096]);

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe-identify-overlay")
            .expect("create scratch directory");
    let path: PathBuf = scratch.path().join("overlaid.exe");
    std::fs::write(&path, &bytes).expect("write the overlaid image");

    let bin: PathBuf = cargo_bin();
    let output: Output = Command::new(&bin)
        .arg("identify")
        .arg(&path)
        .arg("--coverage")
        .arg("--json")
        .output()
        .unwrap_or_else(|error| panic!("run {}: {error}", bin.display()));
    assert!(output.status.success(), "identify must accept an overlay");
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("identify must emit json");
    let coverage: &serde_json::Value = report.get("coverage").expect("coverage");

    let unclaimed: u64 = coverage
        .get("unclaimed_bytes")
        .and_then(serde_json::Value::as_u64)
        .expect("unclaimed_bytes");
    assert!(
        unclaimed >= 4096,
        "4096 appended bytes belong to no declared structure, so they must be reported unclaimed, \
         got {unclaimed}"
    );
    let complete: bool = coverage
        .get("complete")
        .and_then(serde_json::Value::as_bool)
        .expect("complete");
    assert!(
        !complete,
        "an image carrying an overlay is not fully accounted for"
    );

    let covers_overlay: bool = coverage
        .get("regions")
        .and_then(serde_json::Value::as_array)
        .expect("regions")
        .iter()
        .any(|region: &serde_json::Value| {
            region.get("class").and_then(serde_json::Value::as_str) == Some("unclaimed")
                && region.get("start").and_then(serde_json::Value::as_u64) == Some(clean_len)
        });
    assert!(
        covers_overlay,
        "the unclaimed run must start where the original image ended, at 0x{clean_len:x}"
    );
}
