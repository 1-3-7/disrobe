#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use common::{run_disrobe, temp_dir};

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/electron-app")
        .join(name)
}

#[test]
fn disrobe_electron_reports_fuses_and_checks_the_archive_beside_the_executable() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("electron-cli");
    let executable: PathBuf = scratch.path().join("Sample.exe");
    std::fs::copy(corpus("fake_electron.exe"), &executable).expect("copy executable");
    std::fs::create_dir_all(scratch.path().join("resources")).expect("resources dir");
    let archive: PathBuf = scratch.path().join("resources").join("app.asar");
    std::fs::copy(corpus("app.asar"), &archive).expect("copy archive");
    let executable: &str = executable.to_str().expect("utf8 path");

    let run: common::Run = run_disrobe(&["--json", "electron", executable]);
    assert_eq!(run.code, 0, "disrobe electron failed: {}", run.stderr);
    let report: serde_json::Value = serde_json::from_str(&run.stdout).expect("JSON report");
    let fuses: &serde_json::Value = &report["executable"]["fuse_wires"][0]["fuses"];
    assert_eq!(fuses[0]["name"], "RunAsNode");
    assert_eq!(fuses[0]["state"], "enabled");
    assert_eq!(fuses[4]["state"], "disabled");
    assert_eq!(report["archives"][0]["header_matches_declared"], true);

    let text: common::Run = run_disrobe(&["electron", executable]);
    assert_eq!(text.code, 0, "disrobe electron failed: {}", text.stderr);
    assert!(
        text.stdout.contains("ELECTRON_RUN_AS_NODE"),
        "{}",
        text.stdout
    );
    assert!(
        text.stdout.contains("matches the declared hash"),
        "{}",
        text.stdout
    );

    let mut tampered: Vec<u8> = std::fs::read(&archive).expect("read archive");
    let at: usize = tampered
        .windows(9)
        .position(|window: &[u8]| window == b"\"main.js\"")
        .expect("main.js in the header");
    tampered[at + 4] = b'm';
    std::fs::write(&archive, &tampered).expect("write tampered archive");
    let tampered_run: common::Run = run_disrobe(&["electron", executable]);
    assert_eq!(tampered_run.code, 0, "{}", tampered_run.stderr);
    assert!(
        tampered_run
            .stdout
            .contains("DOES NOT match the declared hash"),
        "{}",
        tampered_run.stdout
    );
}
