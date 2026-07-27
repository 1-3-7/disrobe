#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use common::{run_disrobe, temp_dir, temp_path, write_bytes};

const fn align_up(value: usize, align: usize) -> usize {
    value.div_ceil(align) * align
}

fn pickle_wrap(json: &[u8], data: &[u8]) -> Vec<u8> {
    let json_len: u32 = u32::try_from(json.len()).unwrap();
    let aligned: usize = align_up(json.len(), 4);
    let payload_size: u32 = u32::try_from(aligned).unwrap() + 4;
    let header_buf_len: u32 = payload_size + 4;
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&4u32.to_le_bytes());
    out.extend_from_slice(&header_buf_len.to_le_bytes());
    out.extend_from_slice(&payload_size.to_le_bytes());
    out.extend_from_slice(&json_len.to_le_bytes());
    out.extend_from_slice(json);
    out.extend(std::iter::repeat_n(0u8, aligned - json.len()));
    out.extend_from_slice(data);
    out
}

fn synth_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut header: String = String::from(r#"{"files":{"#);
    let mut data: Vec<u8> = Vec::new();
    for (i, (name, body)) in files.iter().enumerate() {
        if i > 0 {
            header.push(',');
        }
        let offset: usize = data.len();
        let size: usize = body.len();
        let _: std::fmt::Result =
            write!(header, r#""{name}":{{"size":{size},"offset":"{offset}"}}"#);
        data.extend_from_slice(body);
    }
    header.push_str("}}");
    pickle_wrap(header.as_bytes(), &data)
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", path.display()))
}

#[test]
fn webview_carves_electron_asar_to_disk() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("webview-electron", "exe");
    let asar: Vec<u8> = synth_asar(&[
        ("index.html", b"<html><body>disrobe</body></html>"),
        ("assets/app.js", b"console.log('recovered');"),
    ]);
    let mut host: Vec<u8> = b"MZ\x00\x00fake-electron-host-stub\x00\x00".to_vec();
    host.extend_from_slice(&asar);
    write_bytes(&input, &host);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("webview-electron-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "webview",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "webview carve failed: {}", run.stderr);
    assert!(
        run.stdout.contains("electron"),
        "text summary must name the electron family; stdout:\n{}",
        run.stdout
    );

    let index: PathBuf = out.join("index.html");
    let app: PathBuf = out.join("assets/app.js");
    assert!(
        index.exists(),
        "index.html not carved; stdout:\n{}",
        run.stdout
    );
    assert!(
        app.exists(),
        "assets/app.js not carved; stdout:\n{}",
        run.stdout
    );
    assert_eq!(read(&index), b"<html><body>disrobe</body></html>");
    assert_eq!(read(&app), b"console.log('recovered');");
}

#[test]
fn webview_json_summary_reports_family_and_per_asset_size() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("webview-electron-json", "exe");
    let asar: Vec<u8> = synth_asar(&[("main.js", b"module.exports = 42;")]);
    let mut host: Vec<u8> = b"MZ\x00\x00fake-electron-host-stub\x00\x00".to_vec();
    host.extend_from_slice(&asar);
    write_bytes(&input, &host);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("webview-electron-json-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "--json",
        "webview",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_eq!(run.code, 0, "webview carve failed: {}", run.stderr);

    let summary: serde_json::Value =
        serde_json::from_str(&run.stdout).expect("stdout must be valid JSON");
    assert_eq!(summary["family"], "electron");
    assert_eq!(summary["asset_count"].as_u64(), Some(1));
    let assets: &Vec<serde_json::Value> = summary["assets"]
        .as_array()
        .expect("assets must be an array");
    assert_eq!(assets.len(), 1);
    assert_eq!(assets[0]["path"], "main.js");
    assert_eq!(
        assets[0]["bytes"].as_u64(),
        Some(b"module.exports = 42;".len() as u64)
    );
}

#[test]
fn webview_rejects_input_with_no_recognized_frontend() {
    let (_input_scratch, input): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("webview-none", "bin");
    write_bytes(&input, &[0u8; 512]);
    let out_scratch: disrobe_core::scratch::ScratchDir = temp_dir("webview-none-out");
    let out: PathBuf = out_scratch.path().to_path_buf();

    let run: common::Run = run_disrobe(&[
        "webview",
        input.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert_ne!(run.code, 0, "an input with no webview frontend must fail");
    assert!(
        run.stderr.contains("DR-WEBVIEW"),
        "failure must surface a DR-WEBVIEW error code; stderr:\n{}",
        run.stderr
    );
}
